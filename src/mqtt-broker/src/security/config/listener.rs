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
use crate::security::config::schema::SecurityConfig;

/// Trait for listening to configuration changes
#[allow(async_fn_in_trait)]
pub trait ConfigChangeListener {
    /// Called when the entire security configuration changes
    async fn on_config_changed(
        &self,
        old_config: &SecurityConfig,
        new_config: &SecurityConfig,
    ) -> Result<(), MqttBrokerError>;

    /// Called when authentication provider configuration changes
    async fn on_authn_provider_changed(
        &self,
        provider_id: &str,
        old_config: &SecurityConfig,
        new_config: &SecurityConfig,
    ) -> Result<(), MqttBrokerError>;

    /// Called when authorization provider configuration changes
    async fn on_authz_provider_changed(
        &self,
        provider_id: &str,
        old_config: &SecurityConfig,
        new_config: &SecurityConfig,
    ) -> Result<(), MqttBrokerError>;
}

/// Enum wrapper for different config listeners to enable dynamic dispatch
/// Note: This is currently a placeholder but prepared for future listener implementations
#[derive(Clone)]
pub enum ConfigChangeListenerType {
    /// Placeholder variant for an empty listener (does nothing)
    #[allow(dead_code)]
    NoOp,
}

impl ConfigChangeListener for ConfigChangeListenerType {
    async fn on_config_changed(
        &self,
        _old_config: &SecurityConfig,
        _new_config: &SecurityConfig,
    ) -> Result<(), MqttBrokerError> {
        match self {
            ConfigChangeListenerType::NoOp => {
                // Do nothing for now
            }
        }
        Ok(())
    }

    async fn on_authn_provider_changed(
        &self,
        _provider_id: &str,
        _old_config: &SecurityConfig,
        _new_config: &SecurityConfig,
    ) -> Result<(), MqttBrokerError> {
        match self {
            ConfigChangeListenerType::NoOp => {
                // Do nothing for now
            }
        }
        Ok(())
    }

    async fn on_authz_provider_changed(
        &self,
        _provider_id: &str,
        _old_config: &SecurityConfig,
        _new_config: &SecurityConfig,
    ) -> Result<(), MqttBrokerError> {
        match self {
            ConfigChangeListenerType::NoOp => {
                // Do nothing for now
            }
        }
        Ok(())
    }
}
