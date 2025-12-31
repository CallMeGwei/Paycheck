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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operator {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: OperatorRole,
    #[serde(skip_serializing)]
    pub api_key_hash: String,
    pub created_at: i64,
    pub created_by: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOperator {
    pub email: String,
    pub name: String,
    pub role: OperatorRole,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOperator {
    pub name: Option<String>,
    pub role: Option<OperatorRole>,
}
