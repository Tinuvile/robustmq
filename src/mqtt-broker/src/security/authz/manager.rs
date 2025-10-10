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

use crate::{
    handler::cache::MQTTCacheManager,
    security::authz::{AuthzRequest, AuthzResult, AuthzSource},
};
use std::sync::Arc;
use tracing::{debug, error, warn};

pub struct AuthzManager {
    sources: Vec<Box<dyn AuthzSource + Send + Sync>>,
    #[allow(dead_code)]
    cache_manager: Arc<MQTTCacheManager>, // todo: cache
    default_allow: bool,
}

impl AuthzManager {
    pub fn new(cache_manager: Arc<MQTTCacheManager>) -> Self {
        let sources: Vec<Box<dyn AuthzSource + Send + Sync>> = Vec::new();

        Self {
            sources,
            cache_manager,
            default_allow: false, // default deny strategy
        }
    }

    /// Create AuthzManager with sources based on storage config
    /// This is where AuthzConfig should be used to create specific sources
    pub fn with_sources(
        cache_manager: Arc<MQTTCacheManager>,
        sources: Vec<Box<dyn AuthzSource + Send + Sync>>,
    ) -> Self {
        Self {
            sources,
            cache_manager,
            default_allow: false,
        }
    }

    pub async fn check_permission(&self, request: &AuthzRequest) -> bool {
        debug!(
            "Checking permission for user: {}, topic: {}, action: {:?}",
            request.username, request.topic, request.action
        );

        // iterate all authz sources
        for (index, source) in self.sources.iter().enumerate() {
            match source.check_permission(request.clone()).await {
                Ok(AuthzResult::Allow) => {
                    debug!(
                        "Permission allowed by source #{} for user: {}",
                        index, request.username
                    );
                    return true;
                }
                Ok(AuthzResult::Deny) => {
                    debug!(
                        "Permission denied by source #{} for user: {}",
                        index, request.username
                    );
                    return false;
                }
                Ok(AuthzResult::Ignore) => {
                    debug!(
                        "Permission ignored by source #{} for user: {}",
                        index, request.username
                    );
                    continue;
                }
                Err(e) => {
                    error!(
                        "Error checking permission with source #{}: {} for user: {}",
                        index, e, request.username
                    );
                    continue; // continue to next source
                }
            }
        }

        // all sources return Ignore or default strategy when error
        warn!(
            "No explicit permission found for user: {}, topic: {}, using default: {}",
            request.username, request.topic, self.default_allow
        );

        self.default_allow
    }

    /// add authz source
    pub fn add_source(&mut self, source: Box<dyn AuthzSource + Send + Sync>) {
        self.sources.push(source);
    }

    /// get source count
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// set default allow strategy
    pub fn set_default_allow(&mut self, allow: bool) {
        self.default_allow = allow;
    }
}
