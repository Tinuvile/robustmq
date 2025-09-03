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
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTAuthnConfig {
    /// JWT 来源位置：password 或 username 字段
    pub from: JWTSource,
    /// JWT 签名验证配置
    pub signature: JWTSignatureConfig,
    /// JWT Claims 验证配置
    pub verify: JWTVerifyConfig,
    /// 用户信息映射配置
    pub user_info_mapping: UserInfoMapping,
}

impl Default for JWTAuthnConfig {
    fn default() -> Self {
        Self {
            from: JWTSource::Password,
            signature: JWTSignatureConfig::default(),
            verify: JWTVerifyConfig::default(),
            user_info_mapping: UserInfoMapping::default(),
        }
    }
}

/// JWT 在 MQTT CONNECT 报文中的位置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JWTSource {
    /// 从 Password 字段获取 JWT
    #[serde(rename = "password")]
    Password,
    /// 从 Username 字段获取 JWT
    #[serde(rename = "username")]
    Username,
}

/// JWT 签名验证配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum JWTSignatureConfig {
    /// 对称密钥签名（HMAC-based）
    #[serde(rename = "hmac-based")]
    HmacBased {
        /// 加密算法
        algorithm: HmacAlgorithm,
        /// 用于校验签名的密钥
        secret: String,
        /// Secret 是否需要 Base64 解码
        secret_base64_encode: bool,
    },
    /// 非对称密钥签名（Public-key）
    #[serde(rename = "public-key")]
    PublicKey {
        /// 加密算法
        algorithm: PublicKeyAlgorithm,
        /// PEM 格式的公钥
        public_key: String,
    },
}

impl Default for JWTSignatureConfig {
    fn default() -> Self {
        Self::HmacBased {
            algorithm: HmacAlgorithm::HS256,
            secret: "your-secret-key".to_string(),
            secret_base64_encode: false,
        }
    }
}

/// HMAC 算法类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HmacAlgorithm {
    #[serde(rename = "HS256")]
    HS256,
    #[serde(rename = "HS384")]
    HS384,
    #[serde(rename = "HS512")]
    HS512,
}

/// 公钥算法类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PublicKeyAlgorithm {
    #[serde(rename = "RS256")]
    RS256,
    #[serde(rename = "RS384")]
    RS384,
    #[serde(rename = "RS512")]
    RS512,
    #[serde(rename = "ES256")]
    ES256,
    #[serde(rename = "ES384")]
    ES384,
    #[serde(rename = "ES512")]
    ES512,
}

/// JWT Claims 验证配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTVerifyConfig {
    /// 是否验证 exp（过期时间）
    pub verify_exp: bool,
    /// 是否验证 nbf（生效时间）
    pub verify_nbf: bool,
    /// 是否验证 iat（签发时间）
    pub verify_iat: bool,
    /// 期望的 iss（签发者）值
    pub expected_issuer: Option<String>,
    /// 期望的 aud（受众）值
    pub expected_audience: Option<Vec<String>>,
    /// 时间容差（处理时钟偏差）
    pub leeway: Duration,
    /// 自定义 Claims 验证规则
    pub custom_claims: HashMap<String, ClaimVerifyRule>,
}

impl Default for JWTVerifyConfig {
    fn default() -> Self {
        Self {
            verify_exp: true,
            verify_nbf: true,
            verify_iat: false,
            expected_issuer: None,
            expected_audience: None,
            leeway: Duration::from_secs(60), // 1分钟容差
            custom_claims: HashMap::new(),
        }
    }
}

/// Claim 验证规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClaimVerifyRule {
    /// 必须等于指定值
    #[serde(rename = "equals")]
    Equals(serde_json::Value),
    /// 必须包含在指定列表中
    #[serde(rename = "in")]
    In(Vec<serde_json::Value>),
    /// 必须匹配正则表达式
    #[serde(rename = "regex")]
    Regex(String),
    /// 必须存在（非空）
    #[serde(rename = "required")]
    Required,
}

/// 用户信息映射配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfoMapping {
    /// Username 字段在 JWT Claims 中的路径
    pub username_claim: String,
    /// 是否为超级用户的字段路径（可选）
    pub is_superuser_claim: Option<String>,
    /// 其他用户属性映射
    pub attribute_mapping: HashMap<String, String>,
}

impl Default for UserInfoMapping {
    fn default() -> Self {
        Self {
            username_claim: "sub".to_string(), // 标准的 JWT subject claim
            is_superuser_claim: Some("is_superuser".to_string()),
            attribute_mapping: HashMap::new(),
        }
    }
}

impl JWTAuthnConfig {
    pub fn validate(&self) -> Result<(), String> {
        // 验证签名配置
        match &self.signature {
            JWTSignatureConfig::HmacBased { secret, .. } => {
                if secret.is_empty() {
                    return Err("HMAC secret cannot be empty".to_string());
                }
            }
            JWTSignatureConfig::PublicKey { public_key, .. } => {
                if public_key.is_empty() {
                    return Err("Public key cannot be empty".to_string());
                }
                // 可以添加 PEM 格式验证
                if !public_key.contains("-----BEGIN") {
                    return Err("Public key should be in PEM format".to_string());
                }
            }
        }

        // 验证用户信息映射
        if self.user_info_mapping.username_claim.is_empty() {
            return Err("username_claim cannot be empty".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_config_default() {
        let config = JWTAuthnConfig::default();
        assert!(matches!(config.from, JWTSource::Password));
        assert!(matches!(
            config.signature,
            JWTSignatureConfig::HmacBased { .. }
        ));
        assert_eq!(config.user_info_mapping.username_claim, "sub");
    }

    #[test]
    fn test_jwt_signature_serialization() {
        let hmac_config = JWTSignatureConfig::HmacBased {
            algorithm: HmacAlgorithm::HS256,
            secret: "my-secret".to_string(),
            secret_base64_encode: true,
        };

        let json = serde_json::to_string(&hmac_config).unwrap();
        assert!(json.contains("hmac-based"));
        assert!(json.contains("HS256"));

        let public_key_config = JWTSignatureConfig::PublicKey {
            algorithm: PublicKeyAlgorithm::RS256,
            public_key: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string(),
        };

        let json = serde_json::to_string(&public_key_config).unwrap();
        assert!(json.contains("public-key"));
        assert!(json.contains("RS256"));
    }

    #[test]
    fn test_config_validation() {
        let mut config = JWTAuthnConfig::default();

        // 默认配置应该有效
        assert!(config.validate().is_ok());

        // 空的 secret 应该无效
        if let JWTSignatureConfig::HmacBased { ref mut secret, .. } = config.signature {
            *secret = "".to_string();
        }
        assert!(config.validate().is_err());
    }
}
