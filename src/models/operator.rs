use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsRefStr, EnumString)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum OperatorRole {
    Owner,
    Admin,
    View,
}

impl OperatorRole {
    /// Returns true if this role can manage other operators (create, update, delete)
    pub fn can_manage_operators(&self) -> bool {
        matches!(self, OperatorRole::Owner)
    }
}

/// Operator record - links a user to system-level operator role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operator {
    pub id: String,
    pub user_id: String,
    pub role: OperatorRole,
    pub created_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

/// Operator with user info joined (for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorWithUser {
    /// Internal ID - not exposed in API responses (use user_id instead)
    #[serde(skip_serializing)]
    pub id: String,
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub role: OperatorRole,
    pub created_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOperator {
    pub user_id: String,
    pub role: OperatorRole,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOperator {
    pub role: Option<OperatorRole>,
}
