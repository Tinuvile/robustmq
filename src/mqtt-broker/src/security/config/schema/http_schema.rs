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
pub struct HTTPAuthnConfig {
    /// HTTP 请求方式
    pub method: HTTPMethod,
    /// HTTP 服务 URL 地址
    pub url: String,
    /// 调用条件（Variform 表达式）
    pub condition: Option<String>,
    /// HTTP 请求头（可选）
    pub headers: Option<HashMap<String, String>>,
    /// 是否启用 TLS
    pub enable_tls: bool,
    /// 请求体模板（支持占位符）
    pub body: HTTPRequestBody,
    /// 请求超时时间
    pub request_timeout: Duration,
}

impl Default for HTTPAuthnConfig {
    fn default() -> Self {
        Self {
            method: HTTPMethod::Post,
            url: "http://127.0.0.1:8080/auth".to_string(),
            condition: None,
            headers: Some({
                let mut headers = HashMap::new();
                headers.insert("Content-Type".to_string(), "application/json".to_string());
                headers
            }),
            enable_tls: false,
            body: HTTPRequestBody::default(),
            request_timeout: Duration::from_secs(5),
        }
    }
}

/// HTTP 请求方式
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HTTPMethod {
    /// GET 请求（注意：不推荐，可能在日志中暴露敏感信息）
    #[serde(rename = "get")]
    Get,
    /// POST 请求（推荐）
    #[serde(rename = "post")]
    Post,
}

/// HTTP 请求体配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HTTPRequestBody {
    /// 请求体模板（JSON格式）
    pub template: String,
    /// 支持的占位符说明
    #[serde(skip)]
    pub supported_placeholders: Vec<&'static str>,
}

impl Default for HTTPRequestBody {
    fn default() -> Self {
        Self {
            template: r#"{
  "username": "${username}",
  "password": "${password}",
  "clientid": "${clientid}",
  "ipaddress": "${ipaddress}",
  "protocol": "${protocol}",
  "listener": "${listener}"
}"#
            .to_string(),
            supported_placeholders: vec![
                "${username}",         // 用户名
                "${password}",         // 密码
                "${clientid}",         // 客户端ID
                "${ipaddress}",        // 客户端IP地址
                "${protocol}",         // 协议类型（mqtt, websocket等）
                "${listener}",         // 监听器名称
                "${peername}",         // 对端地址
                "${cert_subject}",     // 证书主题（TLS连接）
                "${cert_common_name}", // 证书通用名称
            ],
        }
    }
}

/// HTTP 授权配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HTTPAuthzConfig {
    /// HTTP 请求方式
    pub method: HTTPMethod,
    /// HTTP 服务 URL 地址
    pub url: String,
    /// 调用条件
    pub condition: Option<String>,
    /// HTTP 请求头（可选）
    pub headers: Option<HashMap<String, String>>,
    /// 是否启用 TLS
    pub enable_tls: bool,
    /// 请求体模板
    pub body: HTTPAuthzRequestBody,
    /// 请求超时时间
    pub request_timeout: Duration,
}

impl Default for HTTPAuthzConfig {
    fn default() -> Self {
        Self {
            method: HTTPMethod::Post,
            url: "http://127.0.0.1:8080/authz".to_string(),
            condition: None,
            headers: Some({
                let mut headers = HashMap::new();
                headers.insert("Content-Type".to_string(), "application/json".to_string());
                headers
            }),
            enable_tls: false,
            body: HTTPAuthzRequestBody::default(),
            request_timeout: Duration::from_secs(5),
        }
    }
}

/// HTTP 授权请求体配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HTTPAuthzRequestBody {
    /// 请求体模板（JSON格式）
    pub template: String,
}

impl Default for HTTPAuthzRequestBody {
    fn default() -> Self {
        Self {
            template: r#"{
  "username": "${username}",
  "clientid": "${clientid}",
  "ipaddress": "${ipaddress}",
  "action": "${action}",
  "topic": "${topic}",
  "qos": "${qos}",
  "retain": "${retain}"
}"#
            .to_string(),
        }
    }
}

impl HTTPAuthnConfig {
    pub fn validate(&self) -> Result<(), String> {
        // 验证 URL 格式
        if self.url.is_empty() {
            return Err("URL cannot be empty".to_string());
        }

        // 简单的 URL 格式检查
        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err("URL must start with http:// or https://".to_string());
        }

        // TLS 警告检查
        if !self.enable_tls
            && self.url.starts_with("http://")
            && self.body.template.contains("${password}")
        {
            // 这里可以发出警告，但不阻止配置
            // 实际使用时应该记录警告日志
        }

        // 验证请求体模板
        if self.body.template.is_empty() {
            return Err("Request body template cannot be empty".to_string());
        }

        // 检查请求体是否为有效的JSON（当method为POST时）
        if matches!(self.method, HTTPMethod::Post) {
            // 尝试验证模板是否为有效JSON结构（替换占位符后）
            let test_template = self
                .body
                .template
                .replace("${username}", "test")
                .replace("${password}", "test")
                .replace("${clientid}", "test")
                .replace("${ipaddress}", "127.0.0.1")
                .replace("${protocol}", "mqtt")
                .replace("${listener}", "default");

            if serde_json::from_str::<serde_json::Value>(&test_template).is_err() {
                return Err("Request body template is not valid JSON".to_string());
            }
        }

        Ok(())
    }

    /// 获取支持的占位符列表
    pub fn supported_placeholders(&self) -> Vec<&'static str> {
        self.body.supported_placeholders.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_config_default() {
        let config = HTTPAuthnConfig::default();
        assert!(matches!(config.method, HTTPMethod::Post));
        assert!(!config.enable_tls);
        assert!(config.headers.is_some());
        assert_eq!(config.request_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_http_method_serialization() {
        let get = HTTPMethod::Get;
        let json = serde_json::to_string(&get).unwrap();
        assert_eq!(json, "\"get\"");

        let post = HTTPMethod::Post;
        let json = serde_json::to_string(&post).unwrap();
        assert_eq!(json, "\"post\"");
    }

    #[test]
    fn test_config_validation() {
        let mut config = HTTPAuthnConfig::default();

        // 默认配置应该有效
        assert!(config.validate().is_ok());

        // 空URL应该无效
        config.url = "".to_string();
        assert!(config.validate().is_err());

        // 无效URL格式
        config.url = "ftp://example.com".to_string();
        assert!(config.validate().is_err());

        // 有效URL
        config.url = "https://api.example.com/auth".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_request_body_json_validation() {
        let mut config = HTTPAuthnConfig::default();

        // 有效的JSON模板
        config.body.template = r#"{"user": "${username}", "pass": "${password}"}"#.to_string();
        assert!(config.validate().is_ok());

        // 无效的JSON模板
        config.body.template = r#"{"user": "${username", "pass": "${password}"}"#.to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_placeholder_replacement() {
        let body = HTTPRequestBody::default();
        let placeholders = body.supported_placeholders;

        assert!(placeholders.contains(&"${username}"));
        assert!(placeholders.contains(&"${password}"));
        assert!(placeholders.contains(&"${clientid}"));
        assert!(placeholders.contains(&"${ipaddress}"));
    }
}
