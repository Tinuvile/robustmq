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
use crate::security::config::provider::ConfigProvider;
use crate::security::config::schema::SecurityConfig;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct APIConfigProvider {
    runtime_config: Arc<RwLock<SecurityConfig>>,
}

impl Default for APIConfigProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl APIConfigProvider {
    pub fn new() -> Self {
        Self {
            runtime_config: Arc::new(RwLock::new(SecurityConfig::default())),
        }
    }

    pub async fn update_runtime_config(&self, config: SecurityConfig) {
        *self.runtime_config.write().await = config;
    }

    pub async fn get_runtime_config(&self) -> SecurityConfig {
        self.runtime_config.read().await.clone()
    }
}

impl ConfigProvider for APIConfigProvider {
    fn name(&self) -> String {
        "api".to_string()
    }

    fn is_writable(&self) -> bool {
        true
    }

    async fn load(&self) -> Result<SecurityConfig, MqttBrokerError> {
        Ok(self.runtime_config.read().await.clone())
    }

    async fn save(&self, config: &SecurityConfig) -> Result<(), MqttBrokerError> {
        *self.runtime_config.write().await = config.clone();
        Ok(())
    }
}
