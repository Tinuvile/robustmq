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

use super::Authentication;
use crate::handler::cache::CacheManager;
use crate::handler::error::MqttBrokerError;
use crate::security::storage::storage_trait::AuthStorageAdapter;
use axum::async_trait;
use bcrypt;
use hex;
use metadata_struct::mqtt::auth_config::AuthConfig;
use pbkdf2::pbkdf2_hmac;
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256, Sha512};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

pub struct MySQLV2 {
    username: String,
    password: String,
    cache_manager: Arc<CacheManager>,
    driver: Arc<dyn AuthStorageAdapter + Send + 'static + Sync>,
}

impl MySQLV2 {
    pub fn new(
        username: String,
        password: String,
        cache_manager: Arc<CacheManager>,
        driver: Arc<dyn AuthStorageAdapter + Send + 'static + Sync>,
    ) -> Self {
        MySQLV2 {
            username,
            password,
            cache_manager,
            driver,
        }
    }

    /// 获取认证配置（从数据库）
    async fn get_auth_config(&self, config_id: Option<u32>) -> Result<AuthConfig, MqttBrokerError> {
        // 将 driver 转换为具体的 MySQLAuthStorageAdapter 类型
        let mysql_adapter = self
            .driver
            .as_any()
            .downcast_ref::<crate::security::storage::mysql::MySQLAuthStorageAdapter>()
            .ok_or_else(|| {
                MqttBrokerError::CommonError("Invalid storage adapter type".to_string())
            })?;

        if let Some(id) = config_id {
            if let Some(config) = mysql_adapter.get_auth_config(id).await? {
                return Ok(config);
            }
        }

        // 如果指定的配置不存在或没有指定配置ID，返回默认配置
        mysql_adapter.get_default_auth_config().await
    }

    /// 验证密码是否匹配
    async fn verify_password(
        &self,
        user: &metadata_struct::mqtt::user::MqttUser,
    ) -> Result<bool, MqttBrokerError> {
        let auth_config = self.get_auth_config(user.auth_config_id).await?;

        match auth_config.hash_algorithm.as_str() {
            "plain" => Ok(user.password_hash == self.password),
            "md5" => self.verify_simple_hash(&user.password_hash, &user.salt, "md5"),
            "sha" | "sha1" => self.verify_simple_hash(&user.password_hash, &user.salt, "sha1"),
            "sha256" => self.verify_sha256(&user.password_hash, &user.salt, &auth_config),
            "sha512" => self.verify_sha512(&user.password_hash, &user.salt, &auth_config),
            "bcrypt" => self.verify_bcrypt(&user.password_hash),
            "pbkdf2" => self.verify_pbkdf2(&user.password_hash, &user.salt, &auth_config),
            _ => Err(MqttBrokerError::UnsupportedHashAlgorithm(
                auth_config.hash_algorithm.clone(),
            )),
        }
    }

    /// 验证 SHA256 哈希
    fn verify_sha256(
        &self,
        stored_hash: &str,
        salt: &Option<String>,
        config: &AuthConfig,
    ) -> Result<bool, MqttBrokerError> {
        let combinations = self.generate_password_combinations(salt, &config.salt_mode);

        for combination in combinations {
            let mut hasher = Sha256::new();
            hasher.update(combination.as_bytes());
            let hash_result = hex::encode(hasher.finalize());

            if hash_result.to_lowercase() == stored_hash.to_lowercase() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// 验证 SHA512 哈希
    fn verify_sha512(
        &self,
        stored_hash: &str,
        salt: &Option<String>,
        config: &AuthConfig,
    ) -> Result<bool, MqttBrokerError> {
        let combinations = self.generate_password_combinations(salt, &config.salt_mode);

        for combination in combinations {
            let mut hasher = Sha512::new();
            hasher.update(combination.as_bytes());
            let hash_result = hex::encode(hasher.finalize());

            if hash_result.to_lowercase() == stored_hash.to_lowercase() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// 简化的哈希验证（用于MD5/SHA1等暂不完全支持的算法）
    fn verify_simple_hash(
        &self,
        stored_hash: &str,
        salt: &Option<String>,
        algorithm: &str,
    ) -> Result<bool, MqttBrokerError> {
        let combinations = self.generate_password_combinations(salt, "suffix");

        for combination in combinations {
            let mut hasher = DefaultHasher::new();
            combination.hash(&mut hasher);
            let hash_result = format!("{:x}", hasher.finish());

            if hash_result.to_lowercase() == stored_hash.to_lowercase() {
                tracing::warn!("Using simplified hash for algorithm: {}", algorithm);
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// 验证 bcrypt 密码
    fn verify_bcrypt(&self, stored_hash: &str) -> Result<bool, MqttBrokerError> {
        match bcrypt::verify(&self.password, stored_hash) {
            Ok(valid) => Ok(valid),
            Err(e) => Err(MqttBrokerError::PasswordVerificationError(e.to_string())),
        }
    }

    /// 验证 PBKDF2 密码
    fn verify_pbkdf2(
        &self,
        stored_hash: &str,
        salt: &Option<String>,
        config: &AuthConfig,
    ) -> Result<bool, MqttBrokerError> {
        let iterations = config.get_param_as_u32("iterations", 4096);
        let key_length = config.get_param_as_u32("key_length", 32) as usize;

        let combinations = self.generate_password_combinations(salt, &config.salt_mode);

        for combination in combinations {
            let mut derived_key = vec![0u8; key_length];
            pbkdf2_hmac::<Sha256>(
                combination.as_bytes(),
                b"", // PBKDF2 中盐值已经在密码组合中处理
                iterations,
                &mut derived_key,
            );

            let hash_result = hex::encode(derived_key);

            if hash_result.to_lowercase() == stored_hash.to_lowercase() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// 生成密码与盐值的组合
    fn generate_password_combinations(
        &self,
        salt: &Option<String>,
        salt_mode: &str,
    ) -> Vec<String> {
        if let Some(salt_value) = salt {
            match salt_mode {
                "prefix" => vec![format!("{}{}", salt_value, &self.password)],
                "suffix" => vec![format!("{}{}", &self.password, salt_value)],
                "disable" => vec![self.password.clone()],
                _ => vec![
                    format!("{}{}", salt_value, &self.password), // prefix
                    format!("{}{}", &self.password, salt_value), // suffix
                    self.password.clone(),                       // no salt
                ],
            }
        } else {
            vec![self.password.clone()]
        }
    }

    /// 生成随机盐值
    pub fn generate_salt() -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect()
    }

    /// 为新用户生成密码哈希
    pub async fn hash_password(
        password: &str,
        auth_config: &AuthConfig,
    ) -> Result<(String, Option<String>), MqttBrokerError> {
        match auth_config.hash_algorithm.as_str() {
            "plain" => Ok((password.to_string(), None)),
            "md5" => Self::hash_simple(password, &auth_config.salt_mode, "md5"),
            "sha" | "sha1" => Self::hash_simple(password, &auth_config.salt_mode, "sha1"),
            "sha256" => Self::hash_sha256(password, &auth_config.salt_mode),
            "sha512" => Self::hash_sha512(password, &auth_config.salt_mode),
            "bcrypt" => Self::hash_bcrypt(password, auth_config),
            "pbkdf2" => Self::hash_pbkdf2(password, auth_config),
            _ => Err(MqttBrokerError::UnsupportedHashAlgorithm(
                auth_config.hash_algorithm.clone(),
            )),
        }
    }

    /// 生成简化哈希（用于MD5/SHA1等）
    fn hash_simple(
        password: &str,
        salt_mode: &str,
        algorithm: &str,
    ) -> Result<(String, Option<String>), MqttBrokerError> {
        if salt_mode == "disable" {
            let mut hasher = DefaultHasher::new();
            password.hash(&mut hasher);
            return Ok((format!("{:x}", hasher.finish()), None));
        }

        let salt = Self::generate_salt();
        let combination = match salt_mode {
            "prefix" => format!("{}{}", salt, password),
            "suffix" => format!("{}{}", password, salt),
            _ => return Err(MqttBrokerError::InvalidSaltMode(salt_mode.to_string())),
        };

        let mut hasher = DefaultHasher::new();
        combination.hash(&mut hasher);
        tracing::warn!("Using simplified hash for algorithm: {}", algorithm);
        Ok((format!("{:x}", hasher.finish()), Some(salt)))
    }

    /// 生成 SHA256 哈希
    fn hash_sha256(
        password: &str,
        salt_mode: &str,
    ) -> Result<(String, Option<String>), MqttBrokerError> {
        if salt_mode == "disable" {
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            return Ok((hex::encode(hasher.finalize()), None));
        }

        let salt = Self::generate_salt();
        let combination = match salt_mode {
            "prefix" => format!("{}{}", salt, password),
            "suffix" => format!("{}{}", password, salt),
            _ => return Err(MqttBrokerError::InvalidSaltMode(salt_mode.to_string())),
        };

        let mut hasher = Sha256::new();
        hasher.update(combination.as_bytes());
        Ok((hex::encode(hasher.finalize()), Some(salt)))
    }

    /// 生成 SHA512 哈希
    fn hash_sha512(
        password: &str,
        salt_mode: &str,
    ) -> Result<(String, Option<String>), MqttBrokerError> {
        if salt_mode == "disable" {
            let mut hasher = Sha512::new();
            hasher.update(password.as_bytes());
            return Ok((hex::encode(hasher.finalize()), None));
        }

        let salt = Self::generate_salt();
        let combination = match salt_mode {
            "prefix" => format!("{}{}", salt, password),
            "suffix" => format!("{}{}", password, salt),
            _ => return Err(MqttBrokerError::InvalidSaltMode(salt_mode.to_string())),
        };

        let mut hasher = Sha512::new();
        hasher.update(combination.as_bytes());
        Ok((hex::encode(hasher.finalize()), Some(salt)))
    }

    /// 生成 bcrypt 哈希
    fn hash_bcrypt(
        password: &str,
        config: &AuthConfig,
    ) -> Result<(String, Option<String>), MqttBrokerError> {
        let cost = config.get_param_as_u32("salt_rounds", 10).clamp(5, 15);

        match bcrypt::hash(password, cost) {
            Ok(hashed) => Ok((hashed, None)), // bcrypt 自带盐值
            Err(e) => Err(MqttBrokerError::PasswordHashError(e.to_string())),
        }
    }

    /// 生成 PBKDF2 哈希
    fn hash_pbkdf2(
        password: &str,
        config: &AuthConfig,
    ) -> Result<(String, Option<String>), MqttBrokerError> {
        let iterations = config.get_param_as_u32("iterations", 4096);
        let key_length = config.get_param_as_u32("key_length", 32) as usize;

        let salt = Self::generate_salt();
        let mut derived_key = vec![0u8; key_length];

        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            salt.as_bytes(),
            iterations,
            &mut derived_key,
        );

        Ok((hex::encode(derived_key), Some(salt)))
    }
}

pub async fn mysql_v2_check_login(
    driver: &Arc<dyn AuthStorageAdapter + Send + 'static + Sync>,
    cache_manager: &Arc<CacheManager>,
    username: &str,
    password: &str,
) -> Result<bool, MqttBrokerError> {
    let mysql = MySQLV2::new(
        username.to_owned(),
        password.to_owned(),
        cache_manager.clone(),
        driver.clone(),
    );
    match mysql.apply().await {
        Ok(flag) => {
            if flag {
                return Ok(true);
            }
        }
        Err(e) => {
            if e.to_string() == MqttBrokerError::UserDoesNotExist.to_string() {
                return try_get_check_user_by_driver_v2(driver, cache_manager, username, password)
                    .await;
            }
            return Err(e);
        }
    }
    Ok(false)
}

async fn try_get_check_user_by_driver_v2(
    driver: &Arc<dyn AuthStorageAdapter + Send + 'static + Sync>,
    cache_manager: &Arc<CacheManager>,
    username: &str,
    password: &str,
) -> Result<bool, MqttBrokerError> {
    if let Some(user) = driver.get_user(username.to_owned()).await? {
        cache_manager.add_user(user.clone());

        let mysql = MySQLV2::new(
            user.username.clone(),
            password.to_owned(),
            cache_manager.clone(),
            driver.clone(),
        );

        if mysql.apply().await? {
            return Ok(true);
        }
    }

    Ok(false)
}

#[async_trait]
impl Authentication for MySQLV2 {
    async fn apply(&self) -> Result<bool, MqttBrokerError> {
        if let Some(user) = self.cache_manager.user_info.get(&self.username) {
            return self.verify_password(&user).await;
        }
        Err(MqttBrokerError::UserDoesNotExist)
    }
}
