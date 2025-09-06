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

use crate::common::types::ResultMqttBrokerError;
use crate::handler::cache::MQTTCacheManager;
use crate::handler::error::MqttBrokerError;
use crate::security::auth::blacklist::is_blacklist;
use crate::security::auth::is_allow_acl;
use crate::security::config::schema::{
    AuthnProviderConfig, AuthnProviderType, PlaintextAuthnConfig,
};
use crate::security::provider::authn::plaintext::create_plaintext_provider;
use crate::security::provider::authn::{AuthenticationProvider, AuthenticationProviderType};
use crate::security::storage::storage_trait::AuthStorageAdapter;
use crate::subscribe::common::get_sub_topic_id_list;
use common_config::broker::broker_config;
use common_config::config::MqttAuthStorage;
use dashmap::DashMap;
use grpc_clients::pool::ClientPool;
use metadata_struct::acl::mqtt_acl::{MqttAcl, MqttAclAction, MqttAclResourceType};
use metadata_struct::acl::mqtt_blacklist::MqttAclBlackList;
use metadata_struct::mqtt::connection::MQTTConnection;
use metadata_struct::mqtt::user::MqttUser;
use protocol::mqtt::common::{ConnectProperties, Login, QoS, Subscribe};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use storage::mysql::MySQLAuthStorageAdapter;
use storage::placement::PlacementAuthStorageAdapter;
use storage_adapter::StorageType;

pub mod auth; // history, will be removed
pub mod config;
pub mod login; // history, will be removed
pub mod provider;
pub mod storage;

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct AuthDriver {
    cache_manager: Arc<MQTTCacheManager>,
    driver: Arc<dyn AuthStorageAdapter + Send + 'static + Sync>,
    // Authentication providers for different auth methods
    authn_providers: Vec<AuthenticationProviderType>,
}

impl AuthDriver {
    pub fn new(cache_manager: Arc<MQTTCacheManager>, client_pool: Arc<ClientPool>) -> AuthDriver {
        let conf = broker_config();

        let driver = match build_driver(client_pool.clone(), conf.mqtt_auth_storage.clone()) {
            Ok(driver) => driver,
            Err(e) => {
                panic!("{}, auth storage:{:?}", e, conf.mqtt_auth_storage);
            }
        };

        // Initialize authentication providers
        let authn_providers =
            Self::initialize_authn_providers(cache_manager.clone(), driver.clone());

        AuthDriver {
            cache_manager,
            driver,
            authn_providers,
        }
    }

    /// Initialize authentication providers
    /// For now, creates a default plaintext provider
    /// In the future, this will read from configuration
    fn initialize_authn_providers(
        cache_manager: Arc<MQTTCacheManager>,
        storage_driver: Arc<dyn AuthStorageAdapter + Send + 'static + Sync>,
    ) -> Vec<AuthenticationProviderType> {
        let mut providers = Vec::new();

        // Create default plaintext provider
        // TODO: In the future, read this from configuration system
        let plaintext_config = AuthnProviderConfig {
            provider_id: "default-plaintext".to_string(),
            provider_type: AuthnProviderType::Plaintext(PlaintextAuthnConfig {}),
            enable: true,
            priority: 1,
            description: Some("Default plaintext authentication provider".to_string()),
        };

        match create_plaintext_provider(plaintext_config, cache_manager, storage_driver) {
            Ok(provider) => {
                providers.push(AuthenticationProviderType::Plaintext(provider));
            }
            Err(e) => {
                // Log error but don't panic - authentication can still work with fallback
                eprintln!("Failed to create plaintext provider: {}", e);
            }
        }

        providers
    }

    // Permission: Allow && Deny
    pub async fn auth_login_check(
        &self,
        login: &Option<Login>,
        _connect_properties: &Option<ConnectProperties>,
        _socket_addr: &SocketAddr,
    ) -> Result<bool, MqttBrokerError> {
        let cluster = self.cache_manager.get_cluster_config();

        if cluster.mqtt_security.secret_free_login {
            return Ok(true);
        }

        if let Some(info) = login {
            return self.authenticate_user(&info.username, &info.password).await;
        }

        Ok(false)
    }

    /// Authenticate user using configured authentication providers
    async fn authenticate_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<bool, MqttBrokerError> {
        // Sort providers by priority (lower number = higher priority)
        let mut providers = self.authn_providers.clone();
        providers.sort_by_key(|a| a.priority());

        // Try each enabled provider in priority order
        for provider in providers {
            if !provider.is_enabled() {
                continue;
            }

            match provider.authenticate(username, password).await {
                Ok(result) => {
                    if result.success {
                        // Authentication successful
                        return Ok(true);
                    }
                    // Continue to next provider if this one failed
                }
                Err(e) => {
                    // Log error but continue to next provider
                    eprintln!("Authentication provider {} failed: {}", provider.name(), e);
                }
            }
        }

        // All providers failed or no providers available
        Ok(false)
    }

    pub async fn auth_connect_check(&self, connection: &MQTTConnection) -> bool {
        // default true if blacklist check fails
        is_blacklist(&self.cache_manager, connection).unwrap_or(true)
    }

    pub async fn auth_publish_check(
        &self,
        connection: &MQTTConnection,
        topic_name: &str,
        retain: bool,
        qos: QoS,
    ) -> bool {
        is_allow_acl(
            &self.cache_manager,
            connection,
            topic_name,
            MqttAclAction::Publish,
            retain,
            qos,
        )
    }

    pub async fn auth_subscribe_check(
        &self,
        connection: &MQTTConnection,
        subscribe: &Subscribe,
    ) -> bool {
        for filter in subscribe.filters.iter() {
            let topic_list = get_sub_topic_id_list(&self.cache_manager, &filter.path).await;
            for topic in topic_list {
                if !is_allow_acl(
                    &self.cache_manager,
                    connection,
                    &topic,
                    MqttAclAction::Subscribe,
                    false,
                    filter.qos,
                ) {
                    return false;
                }
            }
        }
        true
    }

    // User
    pub async fn read_all_user(&self) -> Result<DashMap<String, MqttUser>, MqttBrokerError> {
        self.driver.read_all_user().await
    }

    pub async fn read_all_acl(&self) -> Result<Vec<MqttAcl>, MqttBrokerError> {
        self.driver.read_all_acl().await
    }

    pub async fn read_all_blacklist(&self) -> Result<Vec<MqttAclBlackList>, MqttBrokerError> {
        self.driver.read_all_blacklist().await
    }

    pub async fn save_user(&self, user_info: MqttUser) -> ResultMqttBrokerError {
        let username = user_info.username.clone();
        if let Some(_user) = self.cache_manager.user_info.get(&username) {
            return Err(MqttBrokerError::UserAlreadyExist);
        }
        self.cache_manager.add_user(user_info.clone());
        self.driver.save_user(user_info).await
    }

    pub async fn delete_user(&self, username: String) -> ResultMqttBrokerError {
        if self.cache_manager.user_info.get(&username).is_none() {
            return Err(MqttBrokerError::UserDoesNotExist);
        }
        self.driver.delete_user(username.clone()).await?;
        self.cache_manager.del_user(username.clone());
        Ok(())
    }

    pub async fn update_user_cache(&self) -> ResultMqttBrokerError {
        let all_users: DashMap<String, MqttUser> = self.driver.read_all_user().await?;

        for entry in all_users.iter() {
            let user = entry.value().clone();
            self.cache_manager.add_user(user);
        }

        let db_usernames: HashSet<String> =
            all_users.iter().map(|user| user.key().clone()).collect();
        self.cache_manager.retain_users(db_usernames);

        Ok(())
    }

    // ACL
    pub async fn save_acl(&self, acl: MqttAcl) -> ResultMqttBrokerError {
        self.cache_manager.add_acl(acl.clone());
        self.driver.save_acl(acl).await
    }

    pub async fn delete_acl(&self, acl: MqttAcl) -> ResultMqttBrokerError {
        self.driver.delete_acl(acl.clone()).await?;
        self.cache_manager.remove_acl(acl.clone());
        Ok(())
    }

    pub async fn update_acl_cache(&self) -> ResultMqttBrokerError {
        let all_acls: Vec<MqttAcl> = self.driver.read_all_acl().await?;

        for acl in all_acls.iter() {
            self.cache_manager.add_acl(acl.to_owned());
        }

        let mut user_acl = HashSet::new();
        let mut client_acl = HashSet::new();

        for acl in all_acls.clone() {
            match acl.resource_type {
                MqttAclResourceType::User => user_acl.insert(acl.resource_name.clone()),
                MqttAclResourceType::ClientId => client_acl.insert(acl.resource_name.clone()),
            };
        }
        self.cache_manager.retain_acls(user_acl, client_acl);

        Ok(())
    }

    // BlackList
    pub async fn save_blacklist(&self, blacklist: MqttAclBlackList) -> ResultMqttBrokerError {
        self.cache_manager.add_blacklist(blacklist.clone());
        self.driver.save_blacklist(blacklist).await
    }

    pub async fn delete_blacklist(&self, blacklist: MqttAclBlackList) -> ResultMqttBrokerError {
        self.driver.delete_blacklist(blacklist.clone()).await?;
        self.cache_manager.remove_blacklist(blacklist.clone());
        Ok(())
    }

    pub async fn update_blacklist_cache(&self) -> ResultMqttBrokerError {
        let all_blacklist = self.driver.read_all_blacklist().await?;

        for acl in all_blacklist.iter() {
            self.cache_manager.add_blacklist(acl.to_owned());
        }

        Ok(())
    }
}

pub fn build_driver(
    client_pool: Arc<ClientPool>,
    auth: MqttAuthStorage,
) -> Result<Arc<dyn AuthStorageAdapter + Send + 'static + Sync>, MqttBrokerError> {
    let storage_type = StorageType::from_str(&auth.storage_type)
        .map_err(|_| MqttBrokerError::UnavailableStorageType)?;
    if matches!(storage_type, StorageType::Placement) {
        let driver = PlacementAuthStorageAdapter::new(client_pool);
        return Ok(Arc::new(driver));
    }

    if matches!(storage_type, StorageType::Mysql) {
        let driver = MySQLAuthStorageAdapter::new(auth.mysql_addr.clone());
        return Ok(Arc::new(driver));
    }

    Err(MqttBrokerError::UnavailableStorageType)
}
