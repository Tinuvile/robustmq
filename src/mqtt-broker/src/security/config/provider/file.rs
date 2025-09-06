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
use std::path::PathBuf;
use tokio::fs;
use tracing::info;

#[derive(Clone)]
pub struct FileConfigProvider {
    config_path: PathBuf,
    readonly: bool,
}

impl FileConfigProvider {
    pub fn new(config_path: PathBuf, readonly: bool) -> Self {
        Self {
            config_path,
            readonly,
        }
    }
}

impl ConfigProvider for FileConfigProvider {
    fn name(&self) -> String {
        "file".to_string()
    }

    fn is_writable(&self) -> bool {
        !self.readonly
    }

    async fn load(&self) -> Result<SecurityConfig, MqttBrokerError> {
        if !self.config_path.exists() {
            info!(
                "File config file {} does not exist, use default config",
                self.config_path.display()
            );
            return Ok(SecurityConfig::default());
        }

        let content = fs::read_to_string(&self.config_path).await.map_err(|e| {
            MqttBrokerError::ConfigLoadError(self.config_path.display().to_string(), e.to_string())
        })?;

        let config = toml::from_str(&content).map_err(|e| {
            MqttBrokerError::ConfigParseError(self.config_path.display().to_string(), e.to_string())
        })?;

        info!("Loaded file config file {}", self.config_path.display());
        Ok(config)
    }

    async fn save(&self, config: &SecurityConfig) -> Result<(), MqttBrokerError> {
        if self.readonly {
            return Err(MqttBrokerError::ConfigSaveError(
                self.config_path.display().to_string(),
                "File config file is readonly".to_string(),
            ));
        }

        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                MqttBrokerError::ConfigSaveError(parent.display().to_string(), e.to_string())
            })?;
        }

        let content = toml::to_string_pretty(config).map_err(|e| {
            MqttBrokerError::ConfigSerializeError(
                self.config_path.display().to_string(),
                e.to_string(),
            )
        })?;

        fs::write(&self.config_path, content).await.map_err(|e| {
            MqttBrokerError::ConfigSaveError(self.config_path.display().to_string(), e.to_string())
        })?;

        info!("Saved file config file {}", self.config_path.display());
        Ok(())
    }
}
