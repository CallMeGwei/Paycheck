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
}

/// Operator with user info joined (for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorWithUser {
    pub id: String,
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub role: OperatorRole,
    pub created_at: i64,
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
