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
    /// Redis 部署模式
    pub deployment_mode: RedisDeploymentMode,
    /// Redis 服务器地址列表
    pub servers: Vec<String>,
    /// Sentinel 主服务器名称（仅在 Sentinel 模式下需要）
    pub sentinel_master_name: Option<String>,
    /// Redis 数据库索引
    pub database: u8,
    /// 认证密码
    pub password: Option<String>,
    /// 连接池大小
    // pub pool_size: u32,
    /// 连接超时时间
    // pub connect_timeout: Duration,
    /// 命令执行超时时间
    // pub query_timeout: Duration,
    /// 用户数据在 Redis 中的键模板
    pub user_key_template: String,
    /// 密码字段名
    pub password_field: String,
    /// 盐值字段名（可选）
    pub salt_field: Option<String>,
    /// 是否为超级用户的字段名（可选）
    pub is_superuser_field: Option<String>,
    /// 密码哈希算法配置
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
    /// Redis 部署模式
    pub deployment_mode: RedisDeploymentMode,
    /// Redis 服务器地址列表
    pub servers: Vec<String>,
    /// Sentinel 主服务器名称（仅在 Sentinel 模式下需要）
    pub sentinel_master_name: Option<String>,
    /// Redis 数据库索引
    pub database: u8,
    /// 认证密码
    pub password: Option<String>,
    /// 连接池大小
    // pub pool_size: u32,
    /// 命令执行超时时间
    // pub query_timeout: Duration,
    /// ACL 规则在 Redis 中的键模板
    pub acl_key_template: String,
    /// 用户角色键模板（用于 RBAC）
    pub user_role_key_template: Option<String>,
    /// 角色权限键模板（用于 RBAC）
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

/// Redis 部署模式
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RedisDeploymentMode {
    /// 单节点模式
    #[serde(rename = "standalone")]
    Standalone,
    /// Sentinel 高可用模式
    #[serde(rename = "sentinel")]
    Sentinel,
    /// 集群模式
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

        // 验证配置是否合理
        assert!(config.sentinel_master_name.is_some());
        assert!(matches!(
            config.deployment_mode,
            RedisDeploymentMode::Sentinel
        ));
    }
}
