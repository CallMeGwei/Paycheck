use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

/// User identity - source of truth for name/email
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub name: String,
}

impl CreateUser {
    pub fn validate(&self) -> Result<()> {
        if self.email.trim().is_empty() {
            return Err(AppError::BadRequest("email cannot be empty".into()));
        }
        if self.name.trim().is_empty() {
            return Err(AppError::BadRequest("name cannot be empty".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub name: Option<String>,
}

impl UpdateUser {
    pub fn validate(&self) -> Result<()> {
        if let Some(ref email) = self.email {
            if email.trim().is_empty() {
                return Err(AppError::BadRequest("email cannot be empty".into()));
            }
        }
        if let Some(ref name) = self.name {
            if name.trim().is_empty() {
                return Err(AppError::BadRequest("name cannot be empty".into()));
            }
        }
        Ok(())
    }
}

/// User's operator role (if any)
#[derive(Debug, Clone, Serialize)]
pub struct UserOperatorRole {
    pub id: String,
    pub role: crate::models::OperatorRole,
}

/// User's membership in an org
#[derive(Debug, Clone, Serialize)]
pub struct UserOrgMembership {
    pub id: String,
    pub org_id: String,
    pub org_name: String,
    pub role: crate::models::OrgMemberRole,
}

/// User with all their roles/memberships
#[derive(Debug, Clone, Serialize)]
pub struct UserWithRoles {
    pub id: String,
    pub email: String,
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
    /// Operator role if user is an operator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<UserOperatorRole>,
    /// Org memberships
    pub memberships: Vec<UserOrgMembership>,
}
