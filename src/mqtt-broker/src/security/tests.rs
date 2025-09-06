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

//! Integration tests for security module migration

#[cfg(test)]
mod integration_tests {
    use crate::common::types::ResultMqttBrokerError;
    use crate::handler::cache::MQTTCacheManager;
    use crate::handler::error::MqttBrokerError;
    use crate::security::config::schema::{
        AuthnProviderConfig, AuthnProviderType, PlaintextAuthnConfig,
    };
    use crate::security::provider::authn::plaintext::create_plaintext_provider;
    use crate::security::provider::authn::{AuthenticationProvider, AuthenticationProviderType};
    use crate::security::storage::storage_trait::AuthStorageAdapter;
    use axum::async_trait;
    use dashmap::DashMap;
    use grpc_clients::pool::ClientPool;
    use metadata_struct::mqtt::user::MqttUser;
    use protocol::mqtt::common::Login;
    use std::sync::Arc;

    // Mock storage adapter for integration testing
    struct IntegrationMockStorage {
        users: DashMap<String, MqttUser>,
    }

    impl IntegrationMockStorage {
        fn new() -> Self {
            Self {
                users: DashMap::new(),
            }
        }

        fn add_test_user(&self, username: &str, password: &str, is_superuser: bool) {
            let user = MqttUser {
                username: username.to_string(),
                password: password.to_string(),
                is_superuser,
            };
            self.users.insert(username.to_string(), user);
        }
    }

    #[async_trait]
    impl AuthStorageAdapter for IntegrationMockStorage {
        async fn read_all_user(&self) -> Result<DashMap<String, MqttUser>, MqttBrokerError> {
            Ok(self.users.clone())
        }

        async fn read_all_acl(
            &self,
        ) -> Result<Vec<metadata_struct::acl::mqtt_acl::MqttAcl>, MqttBrokerError> {
            Ok(Vec::new())
        }

        async fn read_all_blacklist(
            &self,
        ) -> Result<Vec<metadata_struct::acl::mqtt_blacklist::MqttAclBlackList>, MqttBrokerError>
        {
            Ok(Vec::new())
        }

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

    // Simplified AuthDriver for testing (without full dependency injection)
    struct TestAuthDriver {
        #[allow(dead_code)]
        cache_manager: Arc<MQTTCacheManager>,
        authn_providers: Vec<AuthenticationProviderType>,
    }

    impl TestAuthDriver {
        fn new(
            cache_manager: Arc<MQTTCacheManager>,
            storage_driver: Arc<dyn AuthStorageAdapter + Send + 'static + Sync>,
        ) -> Self {
            // Create plaintext provider
            let plaintext_config = AuthnProviderConfig {
                provider_id: "test-plaintext".to_string(),
                provider_type: AuthnProviderType::Plaintext(PlaintextAuthnConfig {}),
                enable: true,
                priority: 1,
                description: Some("Test plaintext provider".to_string()),
            };

            let mut providers = Vec::new();
            if let Ok(provider) =
                create_plaintext_provider(plaintext_config, cache_manager.clone(), storage_driver)
            {
                providers.push(AuthenticationProviderType::Plaintext(provider));
            }

            Self {
                cache_manager,
                authn_providers: providers,
            }
        }

        async fn authenticate_user(
            &self,
            username: &str,
            password: &str,
        ) -> Result<bool, MqttBrokerError> {
            // Sort providers by priority
            let mut providers = self.authn_providers.clone();
            providers.sort_by_key(|a| a.priority());

            for provider in providers {
                if !provider.is_enabled() {
                    continue;
                }

                match provider.authenticate(username, password).await {
                    Ok(result) => {
                        if result.success {
                            return Ok(true);
                        }
                    }
                    Err(_) => {
                        // Continue to next provider
                    }
                }
            }

            Ok(false)
        }

        async fn auth_login_check(&self, login: &Option<Login>) -> Result<bool, MqttBrokerError> {
            if let Some(info) = login {
                return self.authenticate_user(&info.username, &info.password).await;
            }
            Ok(false)
        }
    }

    #[tokio::test]
    async fn test_plaintext_authentication_integration() {
        // Setup test environment
        let client_pool = Arc::new(ClientPool::new(1));
        let cluster_name = "test".to_string();
        let cache_manager = Arc::new(MQTTCacheManager::new(client_pool, cluster_name));

        let storage = Arc::new(IntegrationMockStorage::new());
        storage.add_test_user("alice", "secret123", false);
        storage.add_test_user("bob", "password456", true);

        let auth_driver = TestAuthDriver::new(cache_manager.clone(), storage);

        // Test 1: Valid user authentication from storage
        let login = Some(Login {
            username: "alice".to_string(),
            password: "secret123".to_string(),
        });
        let result = auth_driver.auth_login_check(&login).await.unwrap();
        assert!(result, "Alice should authenticate successfully");

        // Test 2: Valid user authentication from cache (second time)
        let result = auth_driver.auth_login_check(&login).await.unwrap();
        assert!(result, "Alice should authenticate successfully from cache");

        // Test 3: Invalid password
        let login = Some(Login {
            username: "alice".to_string(),
            password: "wrongpassword".to_string(),
        });
        let result = auth_driver.auth_login_check(&login).await.unwrap();
        assert!(!result, "Alice should fail with wrong password");

        // Test 4: Non-existent user
        let login = Some(Login {
            username: "charlie".to_string(),
            password: "anypassword".to_string(),
        });
        let result = auth_driver.auth_login_check(&login).await.unwrap();
        assert!(!result, "Non-existent user should fail");

        // Test 5: Superuser authentication
        let login = Some(Login {
            username: "bob".to_string(),
            password: "password456".to_string(),
        });
        let result = auth_driver.auth_login_check(&login).await.unwrap();
        assert!(result, "Bob should authenticate successfully");

        // Test 6: No login info
        let result = auth_driver.auth_login_check(&None).await.unwrap();
        assert!(!result, "No login info should fail");
    }

    #[tokio::test]
    async fn test_multiple_providers_priority() {
        // This test would verify that multiple providers work correctly with priority
        // For now, we only have plaintext, but this validates the framework

        let client_pool = Arc::new(ClientPool::new(1));
        let cluster_name = "test".to_string();
        let cache_manager = Arc::new(MQTTCacheManager::new(client_pool, cluster_name));

        let storage = Arc::new(IntegrationMockStorage::new());
        storage.add_test_user("testuser", "testpass", false);

        let auth_driver = TestAuthDriver::new(cache_manager, storage);

        assert_eq!(auth_driver.authn_providers.len(), 1);
        assert_eq!(
            auth_driver.authn_providers[0].name(),
            "plaintext-test-plaintext"
        );
        assert!(auth_driver.authn_providers[0].is_enabled());
        assert_eq!(auth_driver.authn_providers[0].priority(), 1);
    }

    #[tokio::test]
    async fn test_provider_authentication_result() {
        // Test that we properly get user information from successful authentication
        let client_pool = Arc::new(ClientPool::new(1));
        let cluster_name = "test".to_string();
        let cache_manager = Arc::new(MQTTCacheManager::new(client_pool, cluster_name));

        let storage = Arc::new(IntegrationMockStorage::new());
        storage.add_test_user("datauser", "datapass", true);

        let plaintext_config = AuthnProviderConfig {
            provider_id: "data-test".to_string(),
            provider_type: AuthnProviderType::Plaintext(PlaintextAuthnConfig {}),
            enable: true,
            priority: 1,
            description: Some("Data test provider".to_string()),
        };

        let provider = create_plaintext_provider(plaintext_config, cache_manager, storage).unwrap();
        let provider_type = AuthenticationProviderType::Plaintext(provider);

        // Test successful authentication
        let result = provider_type
            .authenticate("datauser", "datapass")
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.user_info.is_some());

        let user_info = result.user_info.unwrap();
        assert_eq!(user_info.username, "datauser");
        assert_eq!(user_info.password, "datapass");
        assert!(user_info.is_superuser);

        // Test failed authentication
        let result = provider_type
            .authenticate("datauser", "wrongpass")
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.user_info.is_none());
        assert!(result.error_message.is_some());
    }
}
