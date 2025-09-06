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

use super::schema::SecurityConfig;
use crate::handler::error::MqttBrokerError;
use api::APIConfigProvider;
use file::FileConfigProvider;

pub mod api;
pub mod file;

#[allow(async_fn_in_trait)]
pub trait ConfigProvider {
    /// Provider name
    fn name(&self) -> String;
    /// Provider priority
    // fn priority(&self) -> u32;
    /// Whether the provider is writable
    fn is_writable(&self) -> bool;
    /// Load configuration
    async fn load(&self) -> Result<SecurityConfig, MqttBrokerError>;
    /// Save configuration
    async fn save(&self, config: &SecurityConfig) -> Result<(), MqttBrokerError>;
}

/// Enum wrapper for different config providers to enable dynamic dispatch
#[derive(Clone)]
pub enum ConfigProviderType {
    Api(APIConfigProvider),
    File(FileConfigProvider),
}

impl ConfigProvider for ConfigProviderType {
    fn name(&self) -> String {
        match self {
            ConfigProviderType::Api(provider) => provider.name(),
            ConfigProviderType::File(provider) => provider.name(),
        }
    }

    fn is_writable(&self) -> bool {
        match self {
            ConfigProviderType::Api(provider) => provider.is_writable(),
            ConfigProviderType::File(provider) => provider.is_writable(),
        }
    }

    async fn load(&self) -> Result<SecurityConfig, MqttBrokerError> {
        match self {
            ConfigProviderType::Api(provider) => provider.load().await,
            ConfigProviderType::File(provider) => provider.load().await,
        }
    }

    async fn save(&self, config: &SecurityConfig) -> Result<(), MqttBrokerError> {
        match self {
            ConfigProviderType::Api(provider) => provider.save(config).await,
            ConfigProviderType::File(provider) => provider.save(config).await,
        }
    }
}
