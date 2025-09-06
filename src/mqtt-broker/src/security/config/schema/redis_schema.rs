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

use super::PasswordHashConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisAuthnConfig {
    /// Redis deployment mode
    pub deployment_mode: RedisDeploymentMode,
    /// Redis server address list
    pub servers: Vec<String>,
    /// Sentinel master server name（only required in Sentinel mode）
    pub sentinel_master_name: Option<String>,
    /// Redis database index
    pub database: u8,
    /// Authentication password
    pub password: Option<String>,
    /// Connection pool size
    // pub pool_size: u32,
    /// Connection timeout
    // pub connect_timeout: Duration,
    /// Command execution timeout
    // pub query_timeout: Duration,
    /// User data key template in Redis
    pub user_key_template: String,
    /// Password field name
    pub password_field: String,
    /// Salt field name（optional）
    pub salt_field: Option<String>,
    /// Whether the field is the superuser field（optional）
    pub is_superuser_field: Option<String>,
    /// Password hash algorithm configuration
    pub password_hash_algorithm: PasswordHashConfig,
}

impl Default for RedisAuthnConfig {
    fn default() -> Self {
        Self {
            deployment_mode: RedisDeploymentMode::Standalone,
            servers: vec!["localhost:6379".to_string()],
            sentinel_master_name: None,
            database: 0,
            password: None,
            // pool_size: 10,
            // connect_timeout: Duration::from_secs(10),
            // query_timeout: Duration::from_secs(5),
            user_key_template: "mqtt:user:${username}".to_string(),
            password_field: "password".to_string(),
            salt_field: Some("salt".to_string()),
            is_superuser_field: Some("is_superuser".to_string()),
            password_hash_algorithm: PasswordHashConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisAuthzConfig {
    /// Redis deployment mode
    pub deployment_mode: RedisDeploymentMode,
    /// Redis server address list
    pub servers: Vec<String>,
    /// Sentinel master server name（only required in Sentinel mode）
    pub sentinel_master_name: Option<String>,
    /// Redis database index
    pub database: u8,
    /// Authentication password
    pub password: Option<String>,
    /// Connection pool size
    // pub pool_size: u32,
    /// Command execution timeout
    // pub query_timeout: Duration,
    /// ACL rules key template in Redis
    pub acl_key_template: String,
    /// User role key template（for RBAC）
    pub user_role_key_template: Option<String>,
    /// Role permission key template（for RBAC）
    pub role_permission_key_template: Option<String>,
}

impl Default for RedisAuthzConfig {
    fn default() -> Self {
        Self {
            deployment_mode: RedisDeploymentMode::Standalone,
            servers: vec!["localhost:6379".to_string()],
            sentinel_master_name: None,
            database: 0,
            password: None,
            // pool_size: 10,
            // query_timeout: Duration::from_secs(5),
            acl_key_template: "mqtt:acl:${resource_type}:${resource_name}".to_string(),
            user_role_key_template: Some("mqtt:user_roles:${username}".to_string()),
            role_permission_key_template: Some("mqtt:role_perms:${role}".to_string()),
        }
    }
}

/// Redis deployment mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RedisDeploymentMode {
    /// Single node mode
    #[serde(rename = "standalone")]
    Standalone,
    /// Sentinel high availability mode
    #[serde(rename = "sentinel")]
    Sentinel,
    /// Cluster mode
    #[serde(rename = "cluster")]
    Cluster,
}

impl Default for RedisDeploymentMode {
    fn default() -> Self {
        Self::Standalone
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redis_authn_config_default() {
        let config = RedisAuthnConfig::default();
        assert_eq!(config.servers, vec!["localhost:6379".to_string()]);
        assert_eq!(config.database, 0);
        assert!(matches!(
            config.deployment_mode,
            RedisDeploymentMode::Standalone
        ));
        assert_eq!(config.user_key_template, "mqtt:user:${username}");
    }

    #[test]
    fn test_redis_deployment_mode_serialization() {
        let standalone = RedisDeploymentMode::Standalone;
        let serialized = serde_json::to_string(&standalone).unwrap();
        assert_eq!(serialized, "\"standalone\"");

        let sentinel = RedisDeploymentMode::Sentinel;
        let serialized = serde_json::to_string(&sentinel).unwrap();
        assert_eq!(serialized, "\"sentinel\"");

        let cluster = RedisDeploymentMode::Cluster;
        let serialized = serde_json::to_string(&cluster).unwrap();
        assert_eq!(serialized, "\"cluster\"");
    }

    #[test]
    fn test_redis_config_validation() {
        let config = RedisAuthnConfig {
            deployment_mode: RedisDeploymentMode::Sentinel,
            sentinel_master_name: Some("mymaster".to_string()),
            ..Default::default()
        };

        // Validate configuration is reasonable
        assert!(config.sentinel_master_name.is_some());
        assert!(matches!(
            config.deployment_mode,
            RedisDeploymentMode::Sentinel
        ));
    }
}
