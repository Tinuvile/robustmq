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

pub mod http_schema;
pub mod jwt_schema;
pub mod mysql_schema;
pub mod password_hash_config;
pub mod plaintext_schema;
pub mod postgresql_schema;
pub mod redis_schema;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use http_schema::{HTTPAuthnConfig, HTTPAuthzConfig};
pub use jwt_schema::JWTAuthnConfig;
pub use mysql_schema::{MySQLAuthnConfig, MySQLAuthzConfig};
pub use password_hash_config::{HashAlgorithmType, PBKDF2Config, PasswordHashConfig, SaltPosition};
pub use plaintext_schema::PlaintextAuthnConfig;
pub use postgresql_schema::{PostgreSQLAuthnConfig, PostgreSQLAuthzConfig};
pub use redis_schema::{RedisAuthnConfig, RedisAuthzConfig};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    /// 认证提供者配置
    #[serde(default)]
    pub authentication: HashMap<String, AuthnProviderConfig>,
    /// 授权提供者配置
    #[serde(default)]
    pub authorization: HashMap<String, AuthzProviderConfig>,
    /// 全局安全设置
    pub settings: GlobalSecuritySettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthnProviderConfig {
    pub provider_id: String,
    pub provider_type: AuthnProviderType,
    pub enable: bool,
    pub priority: u32,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "config")]
pub enum AuthnProviderType {
    #[serde(rename = "plaintext")]
    Plaintext(PlaintextAuthnConfig),
    #[serde(rename = "jwt")]
    JWT(JWTAuthnConfig),
    #[serde(rename = "mysql")]
    MySQL(MySQLAuthnConfig),
    #[serde(rename = "postgresql")]
    PostgreSQL(PostgreSQLAuthnConfig),
    #[serde(rename = "redis")]
    Redis(RedisAuthnConfig),
    #[serde(rename = "http")]
    HTTP(HTTPAuthnConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzProviderConfig {
    pub provider_id: String,
    pub provider_type: AuthzProviderType,
    pub enable: bool,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "config")]
pub enum AuthzProviderType {
    #[serde(rename = "mysql")]
    MySQL(MySQLAuthzConfig),
    #[serde(rename = "postgresql")]
    PostgreSQL(PostgreSQLAuthzConfig),
    #[serde(rename = "redis")]
    Redis(RedisAuthnConfig),
    #[serde(rename = "http")]
    HTTP(HTTPAuthnConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalSecuritySettings {
    #[serde(default = "default_secret_free_login")]
    pub secret_free_login: bool,
    // pub cache: GlobalCacheConfig,
    // pub metrics: MetricsConfig,
}

fn default_secret_free_login() -> bool {
    false
}
