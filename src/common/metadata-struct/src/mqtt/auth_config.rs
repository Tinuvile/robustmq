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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct AuthConfig {
    pub id: u32,
    pub name: String,
    pub hash_algorithm: String,
    pub salt_mode: String,
    pub algorithm_params: HashMap<String, serde_json::Value>,
    pub is_default: bool,
}

impl AuthConfig {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(&self).unwrap()
    }

    /// 创建默认认证配置
    pub fn default_config() -> Self {
        AuthConfig {
            id: 1,
            name: "default".to_string(),
            hash_algorithm: "bcrypt".to_string(),
            salt_mode: "disable".to_string(), // bcrypt 自带盐值
            algorithm_params: {
                let mut params = HashMap::new();
                params.insert(
                    "salt_rounds".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(10)),
                );
                params
            },
            is_default: true,
        }
    }

    /// 创建高安全性配置
    pub fn high_security_config() -> Self {
        AuthConfig {
            id: 2,
            name: "high_security".to_string(),
            hash_algorithm: "pbkdf2".to_string(),
            salt_mode: "suffix".to_string(),
            algorithm_params: {
                let mut params = HashMap::new();
                params.insert(
                    "iterations".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(10000)),
                );
                params.insert(
                    "key_length".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(32)),
                );
                params
            },
            is_default: false,
        }
    }

    /// 创建兼容性配置（用于遗留系统）
    pub fn legacy_config() -> Self {
        AuthConfig {
            id: 3,
            name: "legacy".to_string(),
            hash_algorithm: "sha256".to_string(),
            salt_mode: "suffix".to_string(),
            algorithm_params: HashMap::new(),
            is_default: false,
        }
    }

    /// 获取算法参数
    pub fn get_param_as_u32(&self, key: &str, default: u32) -> u32 {
        self.algorithm_params
            .get(key)
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(default)
    }

    /// 获取算法参数
    pub fn get_param_as_string(&self, key: &str, default: &str) -> String {
        self.algorithm_params
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or(default)
            .to_string()
    }
}
