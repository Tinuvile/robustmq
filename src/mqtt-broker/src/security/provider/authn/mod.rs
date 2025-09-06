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

use crate::handler::error::MqttBrokerError;
use metadata_struct::mqtt::user::MqttUser;

pub mod plaintext;

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthnResult {
    /// Whether authentication was successful
    pub success: bool,
    /// User information if authentication succeeded
    pub user_info: Option<MqttUser>,
    /// Error message if authentication failed
    pub error_message: Option<String>,
}

impl AuthnResult {
    /// Create a successful authentication result
    pub fn success(user_info: MqttUser) -> Self {
        Self {
            success: true,
            user_info: Some(user_info),
            error_message: None,
        }
    }

    /// Create a failed authentication result
    pub fn failure(error_message: String) -> Self {
        Self {
            success: false,
            user_info: None,
            error_message: Some(error_message),
        }
    }

    /// Create a simple success result without user info
    pub fn simple_success() -> Self {
        Self {
            success: true,
            user_info: None,
            error_message: None,
        }
    }
}

/// Authentication provider trait
/// Handles user authentication with different methods (plaintext, JWT, HTTP, etc.)
#[allow(async_fn_in_trait)]
pub trait AuthenticationProvider: Send + Sync {
    /// Get provider name
    fn name(&self) -> String;

    /// Authenticate user with username and password
    /// Returns authentication result with user information if successful
    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthnResult, MqttBrokerError>;

    /// Check if provider is enabled
    fn is_enabled(&self) -> bool;

    /// Get provider priority (lower number = higher priority)
    fn priority(&self) -> u32;
}

/// Enum wrapper for different authentication providers to enable dynamic dispatch
#[derive(Clone)]
pub enum AuthenticationProviderType {
    Plaintext(plaintext::PlaintextAuthenticationProvider),
    // TODO: Add other provider types when implemented
    // JWT(jwt::JWTAuthenticationProvider),
    // HTTP(http::HTTPAuthenticationProvider),
    // MySQL(mysql::MySQLAuthenticationProvider),
    // PostgreSQL(postgresql::PostgreSQLAuthenticationProvider),
    // Redis(redis::RedisAuthenticationProvider),
}

impl AuthenticationProvider for AuthenticationProviderType {
    fn name(&self) -> String {
        match self {
            AuthenticationProviderType::Plaintext(provider) => provider.name(),
        }
    }

    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthnResult, MqttBrokerError> {
        match self {
            AuthenticationProviderType::Plaintext(provider) => {
                provider.authenticate(username, password).await
            }
        }
    }

    fn is_enabled(&self) -> bool {
        match self {
            AuthenticationProviderType::Plaintext(provider) => provider.is_enabled(),
        }
    }

    fn priority(&self) -> u32 {
        match self {
            AuthenticationProviderType::Plaintext(provider) => provider.priority(),
        }
    }
}
