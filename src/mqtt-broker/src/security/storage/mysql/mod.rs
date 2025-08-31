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

use crate::common::types::ResultMqttBrokerError;
use crate::handler::error::MqttBrokerError;
use crate::security::AuthStorageAdapter;
use axum::async_trait;
use dashmap::DashMap;
use metadata_struct::acl::mqtt_acl::{
    MqttAcl, MqttAclAction, MqttAclPermission, MqttAclResourceType,
};
use metadata_struct::acl::mqtt_blacklist::MqttAclBlackList;
use metadata_struct::mqtt::auth_config::AuthConfig;
use metadata_struct::mqtt::user::MqttUser;
use mysql::prelude::Queryable;
use mysql::Pool;
use third_driver::mysql::build_mysql_conn_pool;

mod schema;
pub struct MySQLAuthStorageAdapter {
    pool: Pool,
}

impl MySQLAuthStorageAdapter {
    pub fn new(addr: String) -> Self {
        let pool = match build_mysql_conn_pool(&addr) {
            Ok(data) => data,
            Err(e) => {
                panic!("{}", e.to_string());
            }
        };
        MySQLAuthStorageAdapter { pool }
    }

    fn table_user(&self) -> String {
        "mqtt_user".to_string()
    }

    fn table_acl(&self) -> String {
        "mqtt_acl".to_string()
    }

    fn table_auth_config(&self) -> String {
        "auth_config".to_string()
    }

    /// 获取认证配置
    pub async fn get_auth_config(
        &self,
        config_id: u32,
    ) -> Result<Option<AuthConfig>, MqttBrokerError> {
        let mut conn = self.pool.get_conn()?;
        let sql = format!(
            "select id,name,hash_algorithm,salt_mode,algorithm_params,is_default from {} where id={}",
            self.table_auth_config(),
            config_id
        );
        let data: Vec<(u32, String, String, String, String, u8)> = conn.query(sql)?;

        if let Some(row) = data.first() {
            let algorithm_params =
                serde_json::from_str(&row.4).unwrap_or_else(|_| std::collections::HashMap::new());

            return Ok(Some(AuthConfig {
                id: row.0,
                name: row.1.clone(),
                hash_algorithm: row.2.clone(),
                salt_mode: row.3.clone(),
                algorithm_params,
                is_default: row.5 == 1,
            }));
        }

        Ok(None)
    }

    /// 获取默认认证配置
    pub async fn get_default_auth_config(&self) -> Result<AuthConfig, MqttBrokerError> {
        let mut conn = self.pool.get_conn()?;
        let sql = format!(
            "select id,name,hash_algorithm,salt_mode,algorithm_params,is_default from {} where is_default=1 limit 1",
            self.table_auth_config()
        );
        let data: Vec<(u32, String, String, String, String, u8)> = conn.query(sql)?;

        if let Some(row) = data.first() {
            let algorithm_params =
                serde_json::from_str(&row.4).unwrap_or_else(|_| std::collections::HashMap::new());

            return Ok(AuthConfig {
                id: row.0,
                name: row.1.clone(),
                hash_algorithm: row.2.clone(),
                salt_mode: row.3.clone(),
                algorithm_params,
                is_default: row.5 == 1,
            });
        }

        // 如果没有默认配置，返回硬编码的默认配置
        Ok(AuthConfig::default_config())
    }

    /// 获取所有认证配置
    pub async fn get_all_auth_configs(&self) -> Result<Vec<AuthConfig>, MqttBrokerError> {
        let mut conn = self.pool.get_conn()?;
        let sql = format!(
            "select id,name,hash_algorithm,salt_mode,algorithm_params,is_default from {} order by id",
            self.table_auth_config()
        );
        let data: Vec<(u32, String, String, String, String, u8)> = conn.query(sql)?;

        let mut configs = Vec::new();
        for row in data {
            let algorithm_params =
                serde_json::from_str(&row.4).unwrap_or_else(|_| std::collections::HashMap::new());

            configs.push(AuthConfig {
                id: row.0,
                name: row.1,
                hash_algorithm: row.2,
                salt_mode: row.3,
                algorithm_params,
                is_default: row.5 == 1,
            });
        }

        Ok(configs)
    }
}

#[async_trait]
impl AuthStorageAdapter for MySQLAuthStorageAdapter {
    async fn read_all_user(&self) -> Result<DashMap<String, MqttUser>, MqttBrokerError> {
        let mut conn = self.pool.get_conn()?;
        let sql = format!(
            "select username,password_hash,salt,is_superuser,auth_config_id from {}",
            self.table_user()
        );
        let data: Vec<(String, String, Option<String>, u8, Option<u32>)> = conn.query(sql)?;
        let results = DashMap::with_capacity(2);
        for raw in data {
            let user = MqttUser {
                username: raw.0.clone(),
                password_hash: raw.1.clone(),
                salt: raw.2.clone(),
                is_superuser: raw.3 == 1,
                auth_config_id: raw.4,
            };
            results.insert(raw.0.clone(), user);
        }
        return Ok(results);
    }

    async fn read_all_acl(&self) -> Result<Vec<MqttAcl>, MqttBrokerError> {
        let mut conn = self.pool.get_conn()?;
        let sql = format!(
            "select allow, ipaddr, username, clientid, access, topic from {}",
            self.table_acl()
        );
        let data: Vec<(u8, String, String, String, u8, Option<String>)> = conn.query(sql)?;
        let mut results = Vec::new();
        for raw in data {
            let acl = MqttAcl {
                permission: match raw.0 {
                    0 => MqttAclPermission::Deny,
                    1 => MqttAclPermission::Allow,
                    _ => return Err(MqttBrokerError::InvalidAclPermission),
                },
                resource_type: match raw.2.clone().is_empty() {
                    true => MqttAclResourceType::ClientId,
                    false => MqttAclResourceType::User,
                },
                resource_name: match raw.2.clone().is_empty() {
                    true => raw.3.clone(),
                    false => raw.2.clone(),
                },
                topic: raw.5.clone().unwrap_or(String::new()),
                ip: raw.1.clone(),
                action: match raw.4 {
                    0 => MqttAclAction::All,
                    1 => MqttAclAction::Subscribe,
                    2 => MqttAclAction::Publish,
                    3 => MqttAclAction::PubSub,
                    4 => MqttAclAction::Retain,
                    5 => MqttAclAction::Qos,
                    _ => return Err(MqttBrokerError::InvalidAclAction),
                },
            };
            results.push(acl);
        }
        return Ok(results);
    }

    async fn read_all_blacklist(&self) -> Result<Vec<MqttAclBlackList>, MqttBrokerError> {
        return Ok(Vec::new());
    }

    async fn get_user(&self, username: String) -> Result<Option<MqttUser>, MqttBrokerError> {
        let mut conn = self.pool.get_conn()?;
        let sql = format!(
            "select username,password_hash,salt,is_superuser,auth_config_id from {} where username='{}'",
            self.table_user(),
            username
        );
        let data: Vec<(String, String, Option<String>, u8, Option<u32>)> = conn.query(sql)?;
        if let Some(value) = data.first() {
            return Ok(Some(MqttUser {
                username: value.0.clone(),
                password_hash: value.1.clone(),
                salt: value.2.clone(),
                is_superuser: value.3 == 1,
                auth_config_id: value.4,
            }));
        }
        return Ok(None);
    }

    async fn save_user(&self, user_info: MqttUser) -> ResultMqttBrokerError {
        let mut conn = self.pool.get_conn()?;
        let sql = format!(
            "insert into {} ( `username`, `password_hash`, `salt`, `is_superuser`, `auth_config_id`) values ('{}', '{}', {}, '{}', {});",
            self.table_user(),
            user_info.username,
            user_info.password_hash,
            user_info.salt.as_ref().map_or("null".to_string(), |s| format!("'{}'", s)),
            user_info.is_superuser as i32,
            user_info.auth_config_id.map_or("null".to_string(), |id| id.to_string()),
        );
        let _data: Vec<(String, String, Option<String>, u8)> = conn.query(sql)?;
        return Ok(());
    }

    async fn delete_user(&self, username: String) -> ResultMqttBrokerError {
        let mut conn = self.pool.get_conn()?;
        let sql = format!(
            "delete from {} where username = '{}';",
            self.table_user(),
            username
        );
        let _data: Vec<(String, String, Option<String>, u8, Option<String>)> = conn.query(sql)?;
        return Ok(());
    }

    async fn save_acl(&self, acl: MqttAcl) -> ResultMqttBrokerError {
        let allow: u8 = match acl.permission {
            MqttAclPermission::Allow => 1,
            MqttAclPermission::Deny => 0,
        };
        let (username, clientid) = match acl.resource_type.clone() {
            MqttAclResourceType::ClientId => (String::new(), acl.resource_name),
            MqttAclResourceType::User => (acl.resource_name, String::new()),
        };
        let access: u8 = match acl.action {
            MqttAclAction::All => 0,
            MqttAclAction::Subscribe => 1,
            MqttAclAction::Publish => 2,
            MqttAclAction::PubSub => 3,
            MqttAclAction::Retain => 4,
            MqttAclAction::Qos => 5,
        };

        let mut conn = self.pool.get_conn()?;
        let sql = format!(
            "insert into {} (allow, ipaddr, username, clientid, access, topic) values ('{}', '{}', '{}', '{}', '{}', '{}');",
            self.table_acl(),
            allow,
            acl.ip,
            username,
            clientid,
            access,
            acl.topic,
        );

        let _: Vec<(
            u8,
            String,
            Option<String>,
            Option<String>,
            u8,
            Option<String>,
        )> = conn.query(sql)?;

        return Ok(());
    }

    async fn delete_acl(&self, acl: MqttAcl) -> ResultMqttBrokerError {
        let mut conn = self.pool.get_conn()?;
        let sql = match acl.resource_type.clone() {
            MqttAclResourceType::ClientId => format!(
                "delete from {} where clientid = '{}';",
                self.table_acl(),
                acl.resource_name
            ),
            MqttAclResourceType::User => format!(
                "delete from {} where username = '{}';",
                self.table_acl(),
                acl.resource_name
            ),
        };
        let _: Vec<(
            u8,
            String,
            Option<String>,
            Option<String>,
            u8,
            Option<String>,
        )> = conn.query(sql)?;
        return Ok(());
    }
    async fn save_blacklist(&self, _blacklist: MqttAclBlackList) -> ResultMqttBrokerError {
        return Ok(());
    }
    async fn delete_blacklist(&self, _blacklist: MqttAclBlackList) -> ResultMqttBrokerError {
        return Ok(());
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use mysql::params;
    use mysql::prelude::Queryable;
    use third_driver::mysql::build_mysql_conn_pool;

    use super::schema::TAuthUser;
    use super::MySQLAuthStorageAdapter;
    use crate::security::AuthStorageAdapter;

    #[tokio::test]
    #[ignore]
    async fn read_all_user_test() {
        let addr = "mysql://root:123456@127.0.0.1:3306/mqtt".to_string();
        init_user(&addr);
        let auth_mysql = MySQLAuthStorageAdapter::new(addr);
        let result = auth_mysql.read_all_user().await;
        assert!(result.is_ok());
        let res = result.unwrap();
        assert!(res.contains_key("robustmq"));
        let user = res.get("robustmq").unwrap();
        assert_eq!(user.password_hash, "robustmq@2024");
    }

    #[tokio::test]
    #[ignore]
    async fn get_user_test() {
        let addr = "mysql://root:123456@127.0.0.1:3306/mqtt".to_string();
        init_user(&addr);
        let auth_mysql = MySQLAuthStorageAdapter::new(addr);
        let username = "robustmq".to_string();
        let result = auth_mysql.get_user(username).await;
        assert!(result.is_ok());
        let res = result.unwrap();
        let user = res.unwrap();
        assert_eq!(user.password_hash, "robustmq@2024");
    }

    fn init_user(addr: &str) {
        let pool = build_mysql_conn_pool(addr).unwrap();
        let mut conn = pool.get_conn().unwrap();
        let values = [TAuthUser {
            id: 1,
            username: username(),
            password_hash: password(),
            salt: None,
            is_superuser: 1,
            auth_config_id: Some(4), // 使用明文配置
            created: "2024-10-01 10:10:10".to_string(),
        }];
        conn.exec_batch(
            format!("REPLACE INTO {}(username,password_hash,salt,is_superuser,auth_config_id,created_at) VALUES (:username,:password_hash,:salt,:is_superuser,:auth_config_id,:created)",
            "mqtt_user"),
            values.iter().map(|p| {
                params! {
                    "username" => p.username.clone(),
                    "password_hash" => p.password_hash.clone(),
                    "salt" => p.salt.clone(),
                    "auth_config_id" => p.auth_config_id,
                    "is_superuser" => p.is_superuser,
                    "created" => p.created.clone(),
                }
            }),
        ).unwrap();
    }

    fn username() -> String {
        "robustmq".to_string()
    }

    fn password() -> String {
        "robustmq@2024".to_string()
    }
}
