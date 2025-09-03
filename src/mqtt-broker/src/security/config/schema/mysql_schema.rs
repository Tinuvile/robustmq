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
pub struct MySQLAuthnConfig {
    pub server: String,   // "localhost:3306"
    pub database: String, // "mqtt"
    pub username: String, // "root"
    pub password: String, // "password"
    // pub pool_size: u32,
    // pub connect_timeout: Duration,
    pub query: String, // SQL查询模板
    // pub query_timeout: Duration,
    pub password_hash_algorithm: PasswordHashConfig,
}

impl Default for MySQLAuthnConfig {
    fn default() -> Self {
        Self {
            server: "localhost:3306".to_string(),
            database: "mqtt".to_string(),
            username: "root".to_string(),
            password: "".to_string(),
            // pool_size: 10,
            // connect_timeout: Duration::from_secs(10),
            query:
                "SELECT password, salt, is_superuser FROM mqtt_user WHERE username = ${username}"
                    .to_string(),
            // query_timeout: Duration::from_secs(5),
            password_hash_algorithm: PasswordHashConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MySQLAuthzConfig {
    pub server: String,
    pub database: String,
    pub username: String,
    pub password: String,
    // pub pool_size: u32,
    pub query: String,
    // pub query_timeout: Duration,
}
