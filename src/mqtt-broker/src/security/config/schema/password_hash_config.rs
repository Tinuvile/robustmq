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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHashConfig {
    pub algorithm: HashAlgorithmType,
    pub salt_position: SaltPosition,
    pub bcrypt_cost: Option<u32>,
    pub pbkdf2: Option<PBKDF2Config>,
}

impl Default for PasswordHashConfig {
    fn default() -> Self {
        Self {
            algorithm: HashAlgorithmType::Sha256,
            salt_position: SaltPosition::Suffix,
            bcrypt_cost: Some(10),
            pbkdf2: Some(PBKDF2Config::default()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashAlgorithmType {
    #[serde(rename = "plain")]
    Plain,
    #[serde(rename = "md5")]
    Md5,
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "sha512")]
    Sha512,
    #[serde(rename = "bcrypt")]
    Bcrypt,
    #[serde(rename = "pbkdf2")]
    Pbkdf2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SaltPosition {
    #[serde(rename = "prefix")]
    Prefix,
    #[serde(rename = "suffix")]
    Suffix,
    #[serde(rename = "disable")]
    Disable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PBKDF2Config {
    pub iterations: u32,                  // 迭代次数
    pub hash_function: HashAlgorithmType, // 伪随机函数
    pub key_length: Option<u32>,          // 可选的密钥长度
}

impl Default for PBKDF2Config {
    fn default() -> Self {
        Self {
            iterations: 4096,
            hash_function: HashAlgorithmType::Sha256,
            key_length: None,
        }
    }
}
