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
    /// HTTP request method
    pub method: HTTPMethod,
    /// HTTP service URL address
    pub url: String,
    /// Call condition（Variform expression）
    pub condition: Option<String>,
    /// HTTP request headers（optional）
    pub headers: Option<HashMap<String, String>>,
    /// Enable TLS
    pub enable_tls: bool,
    /// Request body template（supports placeholders）
    pub body: HTTPRequestBody,
    /// Request timeout
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

/// HTTP request method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HTTPMethod {
    /// GET request（Note: Not recommended, may expose sensitive information in logs）
    #[serde(rename = "get")]
    Get,
    /// POST request（Recommended）
    #[serde(rename = "post")]
    Post,
}

/// HTTP request body configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HTTPRequestBody {
    /// Request body template（JSON format）
    pub template: String,
    /// Supported placeholders description
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
                "${username}",         // Username
                "${password}",         // Password
                "${clientid}",         // Client ID
                "${ipaddress}",        // Client IP address
                "${protocol}",         // Protocol type（mqtt, websocket etc.）
                "${listener}",         // Listener name
                "${peername}",         // Remote address
                "${cert_subject}",     // Certificate subject（TLS connection）
                "${cert_common_name}", // Certificate common name
            ],
        }
    }
}

/// HTTP authorization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HTTPAuthzConfig {
    /// HTTP request method
    pub method: HTTPMethod,
    /// HTTP service URL
    pub url: String,
    /// Call condition
    pub condition: Option<String>,
    /// HTTP request headers（optional）
    pub headers: Option<HashMap<String, String>>,
    /// Enable TLS
    pub enable_tls: bool,
    /// Request body template
    pub body: HTTPAuthzRequestBody,
    /// Request timeout
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

/// HTTP authorization request body configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HTTPAuthzRequestBody {
    /// Request body template（JSON format）
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
        // Validate URL format
        if self.url.is_empty() {
            return Err("URL cannot be empty".to_string());
        }

        // Simple URL format check
        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err("URL must start with http:// or https://".to_string());
        }

        // TLS warning check
        if !self.enable_tls
            && self.url.starts_with("http://")
            && self.body.template.contains("${password}")
        {
            // Here we can emit warnings, but do not prevent the configuration
            // Actual use should record warning logs
        }

        // Validate request body template
        if self.body.template.is_empty() {
            return Err("Request body template cannot be empty".to_string());
        }

        // Check if the request body is a valid JSON（when method is POST）
        if matches!(self.method, HTTPMethod::Post) {
            // Try to validate if the template is a valid JSON structure（after replacing placeholders）
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

    /// Get supported placeholders list
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

        // Default configuration should be valid
        assert!(config.validate().is_ok());

        // Empty URL should be invalid
        config.url = "".to_string();
        assert!(config.validate().is_err());

        // Invalid URL format
        config.url = "ftp://example.com".to_string();
        assert!(config.validate().is_err());

        // Valid URL
        config.url = "https://api.example.com/auth".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_request_body_json_validation() {
        let mut config = HTTPAuthnConfig::default();

        // Valid JSON template
        config.body.template = r#"{"user": "${username}", "pass": "${password}"}"#.to_string();
        assert!(config.validate().is_ok());

        // Invalid JSON template
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
