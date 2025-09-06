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

use super::{AuthenticationProvider, AuthnResult};
use crate::handler::cache::MQTTCacheManager;
use crate::handler::error::MqttBrokerError;
use crate::security::config::schema::AuthnProviderConfig;
use crate::security::storage::storage_trait::AuthStorageAdapter;
use std::sync::Arc;

/// Plaintext authentication provider
/// Authenticates users with plaintext username/password stored in cache or storage
#[derive(Clone)]
pub struct PlaintextAuthenticationProvider {
    /// Provider configuration
    pub config: AuthnProviderConfig,
    /// Cache manager for user information
    pub cache_manager: Arc<MQTTCacheManager>,
    /// Storage adapter for persistent user data
    pub storage_driver: Arc<dyn AuthStorageAdapter + Send + 'static + Sync>,
}

impl PlaintextAuthenticationProvider {
    /// Create new plaintext authentication provider
    pub fn new(
        config: AuthnProviderConfig,
        cache_manager: Arc<MQTTCacheManager>,
        storage_driver: Arc<dyn AuthStorageAdapter + Send + 'static + Sync>,
    ) -> Self {
        Self {
            config,
            cache_manager,
            storage_driver,
        }
    }

    /// Validate username and password against cached user information
    async fn validate_cached_user(&self, username: &str, password: &str) -> Option<AuthnResult> {
        if let Some(user) = self.cache_manager.user_info.get(username) {
            if user.password == password {
                return Some(AuthnResult::success(user.clone()));
            } else {
                return Some(AuthnResult::failure("Invalid password".to_string()));
            }
        }
        None
    }

    /// Try to get user from storage and validate
    async fn validate_storage_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthnResult, MqttBrokerError> {
        // Try to get user from storage
        if let Some(user) = self.storage_driver.get_user(username.to_owned()).await? {
            // Add user to cache for future lookups
            self.cache_manager.add_user(user.clone());

            // Validate password
            if user.password == password {
                Ok(AuthnResult::success(user))
            } else {
                Ok(AuthnResult::failure("Invalid password".to_string()))
            }
        } else {
            Ok(AuthnResult::failure("User not found".to_string()))
        }
    }
}

impl AuthenticationProvider for PlaintextAuthenticationProvider {
    fn name(&self) -> String {
        format!("plaintext-{}", self.config.provider_id)
    }

    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthnResult, MqttBrokerError> {
        // First check cached user information
        if let Some(result) = self.validate_cached_user(username, password).await {
            return Ok(result);
        }

        // If user not in cache, try to get from storage
        self.validate_storage_user(username, password).await
    }

    fn is_enabled(&self) -> bool {
        self.config.enable
    }

    fn priority(&self) -> u32 {
        self.config.priority
    }
}

/// Create plaintext authentication provider from configuration
pub fn create_plaintext_provider(
    config: AuthnProviderConfig,
    cache_manager: Arc<MQTTCacheManager>,
    storage_driver: Arc<dyn AuthStorageAdapter + Send + 'static + Sync>,
) -> Result<PlaintextAuthenticationProvider, MqttBrokerError> {
    // Validate that this is indeed a plaintext provider
    match &config.provider_type {
        crate::security::config::schema::AuthnProviderType::Plaintext(_plaintext_config) => {
            // For plaintext, the config doesn't contain additional settings
            // All configuration is handled at the provider level
            Ok(PlaintextAuthenticationProvider::new(
                config,
                cache_manager,
                storage_driver,
            ))
        }
        _ => Err(MqttBrokerError::AuthenticationError(
            "Invalid provider type for plaintext authentication".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::config::schema::{AuthnProviderType, PlaintextAuthnConfig};
    use dashmap::DashMap;
    use grpc_clients::pool::ClientPool;
    use metadata_struct::mqtt::user::MqttUser;
    use std::sync::Arc;

    // Mock storage adapter for testing
    struct MockAuthStorageAdapter {
        users: DashMap<String, MqttUser>,
    }

    impl MockAuthStorageAdapter {
        fn new() -> Self {
            Self {
                users: DashMap::new(),
            }
        }

        #[allow(unused)]
        fn add_user(&self, user: MqttUser) {
            self.users.insert(user.username.clone(), user);
        }
    }

    use crate::common::types::ResultMqttBrokerError;
    use axum::async_trait;

    #[async_trait]
    impl AuthStorageAdapter for MockAuthStorageAdapter {
        async fn get_user(&self, username: String) -> Result<Option<MqttUser>, MqttBrokerError> {
            Ok(self.users.get(&username).map(|entry| entry.clone()))
        }

        async fn save_user(&self, user_info: MqttUser) -> ResultMqttBrokerError {
            self.users.insert(user_info.username.clone(), user_info);
            Ok(())
        }

        async fn delete_user(&self, username: String) -> ResultMqttBrokerError {
            self.users.remove(&username);
            Ok(())
        }

        async fn read_all_user(&self) -> Result<DashMap<String, MqttUser>, MqttBrokerError> {
            Ok(self.users.clone())
        }

        async fn read_all_acl(
            &self,
        ) -> Result<Vec<metadata_struct::acl::mqtt_acl::MqttAcl>, MqttBrokerError> {
            Ok(Vec::new())
        }

        async fn save_acl(
            &self,
            _acl: metadata_struct::acl::mqtt_acl::MqttAcl,
        ) -> ResultMqttBrokerError {
            Ok(())
        }

        async fn delete_acl(
            &self,
            _acl: metadata_struct::acl::mqtt_acl::MqttAcl,
        ) -> ResultMqttBrokerError {
            Ok(())
        }

        async fn read_all_blacklist(
            &self,
        ) -> Result<Vec<metadata_struct::acl::mqtt_blacklist::MqttAclBlackList>, MqttBrokerError>
        {
            Ok(Vec::new())
        }

        async fn save_blacklist(
            &self,
            _blacklist: metadata_struct::acl::mqtt_blacklist::MqttAclBlackList,
        ) -> ResultMqttBrokerError {
            Ok(())
        }

        async fn delete_blacklist(
            &self,
            _blacklist: metadata_struct::acl::mqtt_blacklist::MqttAclBlackList,
        ) -> ResultMqttBrokerError {
            Ok(())
        }
    }

    fn setup_test_environment() -> (
        Arc<MQTTCacheManager>,
        Arc<dyn AuthStorageAdapter + Send + 'static + Sync>,
    ) {
        let client_pool = Arc::new(ClientPool::new(1));
        let cluster_name = "test".to_string();
        let cache_manager = Arc::new(MQTTCacheManager::new(client_pool, cluster_name));
        let storage_driver = Arc::new(MockAuthStorageAdapter::new());

        (cache_manager, storage_driver)
    }

    fn create_test_config() -> AuthnProviderConfig {
        AuthnProviderConfig {
            provider_id: "plaintext-test".to_string(),
            provider_type: AuthnProviderType::Plaintext(PlaintextAuthnConfig {}),
            enable: true,
            priority: 1,
            description: Some("Test plaintext provider".to_string()),
        }
    }

    #[tokio::test]
    async fn test_authenticate_cached_user_success() {
        let (cache_manager, storage_driver) = setup_test_environment();
        let config = create_test_config();

        // Add user to cache
        let user = MqttUser {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            is_superuser: false,
        };
        cache_manager.add_user(user.clone());

        let provider = PlaintextAuthenticationProvider::new(config, cache_manager, storage_driver);

        let result = provider.authenticate("testuser", "testpass").await.unwrap();

        assert!(result.success);
        assert!(result.user_info.is_some());
        assert_eq!(result.user_info.unwrap().username, "testuser");
    }

    #[tokio::test]
    async fn test_authenticate_cached_user_wrong_password() {
        let (cache_manager, storage_driver) = setup_test_environment();
        let config = create_test_config();

        // Add user to cache
        let user = MqttUser {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            is_superuser: false,
        };
        cache_manager.add_user(user);

        let provider = PlaintextAuthenticationProvider::new(config, cache_manager, storage_driver);

        let result = provider
            .authenticate("testuser", "wrongpass")
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result.user_info.is_none());
        assert!(result.error_message.is_some());
    }

    #[tokio::test]
    async fn test_authenticate_user_not_found() {
        let (cache_manager, storage_driver) = setup_test_environment();
        let config = create_test_config();

        let provider = PlaintextAuthenticationProvider::new(config, cache_manager, storage_driver);

        let result = provider
            .authenticate("nonexistent", "password")
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result.user_info.is_none());
        assert_eq!(result.error_message.unwrap(), "User not found");
    }

    #[tokio::test]
    async fn test_provider_properties() {
        let (cache_manager, storage_driver) = setup_test_environment();
        let config = create_test_config();

        let provider = PlaintextAuthenticationProvider::new(config, cache_manager, storage_driver);

        assert_eq!(provider.name(), "plaintext-plaintext-test");
        assert!(provider.is_enabled());
        assert_eq!(provider.priority(), 1);
    }

    #[tokio::test]
    async fn test_create_plaintext_provider() {
        let (cache_manager, storage_driver) = setup_test_environment();
        let config = create_test_config();

        let provider = create_plaintext_provider(config, cache_manager, storage_driver).unwrap();

        assert!(provider.is_enabled());
        assert_eq!(provider.name(), "plaintext-plaintext-test");
    }
}
