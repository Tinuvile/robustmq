// Copyright 2023 RobustMQ Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::handler::error::MqttBrokerError;
use crate::security::config::listener::{ConfigChangeListener, ConfigChangeListenerType};
use crate::security::config::provider::{ConfigProvider, ConfigProviderType};
use crate::security::config::schema::{AuthnProviderConfig, AuthzProviderConfig, SecurityConfig};
use crate::security::config::validator::ConfigValidator;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

pub struct SecurityConfigManager {
    current_config: Arc<RwLock<SecurityConfig>>,
    providers: Vec<ConfigProviderType>,
    listeners: Vec<ConfigChangeListenerType>,
    validators: ConfigValidator,
}

impl Default for SecurityConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityConfigManager {
    pub fn new() -> Self {
        Self {
            current_config: Arc::new(RwLock::new(SecurityConfig::default())),
            providers: Vec::new(),
            listeners: Vec::new(),
            validators: ConfigValidator::new(),
        }
    }

    pub fn register_provider(&mut self, provider: ConfigProviderType) {
        self.providers.push(provider);
        // self.providers.sort_by_key(|p| p.priority());
    }

    pub fn register_listener(&mut self, listener: ConfigChangeListenerType) {
        self.listeners.push(listener);
    }

    pub fn register_validator(&mut self, validator: ConfigValidator) {
        self.validators = validator;
    }

    pub async fn load_config(&self) -> Result<SecurityConfig, MqttBrokerError> {
        let mut merged_config = SecurityConfig::default();

        for provider in &self.providers {
            match provider.load().await {
                Ok(config) => {
                    info!("Loaded config from provider: {}", provider.name());
                    merged_config = self.merge_config(merged_config, config)?;
                }
                Err(e) => {
                    warn!(
                        "Failed to load config from provider: {}: {}",
                        provider.name(),
                        e
                    );
                }
            }
        }

        // Update current config
        *self.current_config.write().await = merged_config.clone();

        Ok(merged_config)
    }

    /// Update authentication provider configuration
    pub async fn update_authn_provider(
        &self,
        provider_id: &str,
        config: AuthnProviderConfig,
    ) -> Result<(), MqttBrokerError> {
        let mut current_config = self.current_config.write().await;
        let old_config = current_config.clone();

        current_config
            .authentication
            .insert(provider_id.to_string(), config);
        let new_config = current_config.clone();
        drop(current_config);

        // Persist to writable providers
        self.persist_to_providers(&new_config).await?;

        // Notify listeners
        self.notify_authn_provider_change(provider_id, &old_config, &new_config)
            .await?;

        Ok(())
    }

    /// Update authorization provider configuration
    pub async fn update_authz_provider(
        &self,
        provider_id: &str,
        config: AuthzProviderConfig,
    ) -> Result<(), MqttBrokerError> {
        let mut current_config = self.current_config.write().await;
        let old_config = current_config.clone();

        current_config
            .authorization
            .insert(provider_id.to_string(), config);
        let new_config = current_config.clone();
        drop(current_config);

        // Persist to writable providers
        self.persist_to_providers(&new_config).await?;

        // Notify listeners
        self.notify_authz_provider_change(provider_id, &old_config, &new_config)
            .await?;

        Ok(())
    }

    /// Get current security configuration
    pub async fn get_config(&self) -> SecurityConfig {
        self.current_config.read().await.clone()
    }

    /// Get authentication provider configuration by ID
    pub async fn get_authn_provider_config(
        &self,
        provider_id: &str,
    ) -> Option<AuthnProviderConfig> {
        let config = self.current_config.read().await;
        config.authentication.get(provider_id).cloned()
    }

    /// Get authorization provider configuration by ID
    pub async fn get_authz_provider_config(
        &self,
        provider_id: &str,
    ) -> Option<AuthzProviderConfig> {
        let config = self.current_config.read().await;
        config.authorization.get(provider_id).cloned()
    }

    /// Reload configuration from all providers and notify listeners
    pub async fn reload_config(&self) -> Result<(), MqttBrokerError> {
        let old_config = self.get_config().await;
        let new_config = self.load_config().await?;

        // Notify all listeners about the configuration change
        self.notify_config_change(&old_config, &new_config).await?;

        Ok(())
    }

    /// Merge two security configurations
    /// The new config takes precedence over the base config
    fn merge_config(
        &self,
        mut base: SecurityConfig,
        new: SecurityConfig,
    ) -> Result<SecurityConfig, MqttBrokerError> {
        // Merge authentication providers
        for (id, provider) in new.authentication {
            base.authentication.insert(id, provider);
        }

        // Merge authorization providers
        for (id, provider) in new.authorization {
            base.authorization.insert(id, provider);
        }

        // Settings from new config override base settings
        if new.settings.secret_free_login != base.settings.secret_free_login {
            base.settings.secret_free_login = new.settings.secret_free_login;
        }

        Ok(base)
    }

    /// Persist configuration to all writable providers
    async fn persist_to_providers(&self, config: &SecurityConfig) -> Result<(), MqttBrokerError> {
        for provider in &self.providers {
            if provider.is_writable() {
                if let Err(e) = provider.save(config).await {
                    warn!(
                        "Failed to save config to provider {}: {}",
                        provider.name(),
                        e
                    );
                    // Continue with other providers even if one fails
                }
            }
        }
        Ok(())
    }

    /// Notify all listeners about configuration changes
    async fn notify_config_change(
        &self,
        old_config: &SecurityConfig,
        new_config: &SecurityConfig,
    ) -> Result<(), MqttBrokerError> {
        for listener in &self.listeners {
            if let Err(e) = listener.on_config_changed(old_config, new_config).await {
                warn!("Config change listener failed: {}", e);
                // Continue with other listeners even if one fails
            }
        }
        Ok(())
    }

    /// Notify all listeners about authentication provider changes
    async fn notify_authn_provider_change(
        &self,
        provider_id: &str,
        old_config: &SecurityConfig,
        new_config: &SecurityConfig,
    ) -> Result<(), MqttBrokerError> {
        for listener in &self.listeners {
            if let Err(e) = listener
                .on_authn_provider_changed(provider_id, old_config, new_config)
                .await
            {
                warn!("Authentication provider change listener failed: {}", e);
                // Continue with other listeners even if one fails
            }
        }
        Ok(())
    }

    /// Notify all listeners about authorization provider changes
    async fn notify_authz_provider_change(
        &self,
        provider_id: &str,
        old_config: &SecurityConfig,
        new_config: &SecurityConfig,
    ) -> Result<(), MqttBrokerError> {
        for listener in &self.listeners {
            if let Err(e) = listener
                .on_authz_provider_changed(provider_id, old_config, new_config)
                .await
            {
                warn!("Authorization provider change listener failed: {}", e);
                // Continue with other listeners even if one fails
            }
        }
        Ok(())
    }
}
