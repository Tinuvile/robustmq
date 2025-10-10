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
use axum::async_trait;
use common_base::enum_type::mqtt::acl::mqtt_acl_action::MqttAclAction;
use metadata_struct::acl::mqtt_acl::MqttAcl;
use protocol::mqtt::common::QoS;

/// Authorized data source
pub mod file;
pub mod http;
pub mod manager;
pub mod mysql;
pub mod placement;
pub mod postgresql;
pub mod redis;

#[async_trait]
pub trait AuthzSource {
    async fn check_permission(&self, request: AuthzRequest)
        -> Result<AuthzResult, MqttBrokerError>;

    async fn load_permissions(&self, username: &str) -> Result<Vec<MqttAcl>, MqttBrokerError>;
}

#[derive(Debug, Clone)]
pub struct AuthzRequest {
    pub username: String,
    pub client_id: String,
    pub source_ip: String,
    pub topic: String,
    pub action: MqttAclAction,
    pub qos: Option<QoS>,
    pub retain: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthzResult {
    Allow,
    Deny,
    Ignore,
}
