use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsRefStr, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ActorType {
    Operator,
    OrgMember,
    Public,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: String,
    pub timestamp: i64,
    pub actor_type: ActorType,
    pub actor_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub details: Option<serde_json::Value>,
    pub org_id: Option<String>,
    pub project_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub actor_type: Option<ActorType>,
    pub actor_id: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub org_id: Option<String>,
    pub project_id: Option<String>,
    pub from_timestamp: Option<i64>,
    pub to_timestamp: Option<i64>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

impl Default for AuditLogQuery {
    fn default() -> Self {
        Self {
            actor_type: None,
            actor_id: None,
            action: None,
            resource_type: None,
            resource_id: None,
            org_id: None,
            project_id: None,
            from_timestamp: None,
            to_timestamp: None,
            limit: Some(100),
            offset: Some(0),
        }
    }
}
