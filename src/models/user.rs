use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result, msg};

/// Basic email format validation.
///
/// Validates that email has:
/// - Exactly one @ symbol
/// - Non-empty local part (before @)
/// - Non-empty domain part (after @)
/// - At least one dot in the domain
///
/// This is intentionally permissive to avoid rejecting valid but unusual emails.
/// It's not meant to be RFC 5322 compliant - just a basic sanity check.
fn validate_email_format(email: &str) -> Result<()> {
    let email = email.trim();

    if email.is_empty() {
        return Err(AppError::BadRequest(msg::EMAIL_EMPTY.into()));
    }

    // Check for exactly one @
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return Err(AppError::BadRequest(msg::INVALID_EMAIL_FORMAT.into()));
    }

    let local_part = parts[0];
    let domain_part = parts[1];

    // Local part cannot be empty
    if local_part.is_empty() {
        return Err(AppError::BadRequest(msg::INVALID_EMAIL_FORMAT.into()));
    }

    // Domain cannot be empty and must have at least one dot
    if domain_part.is_empty() || !domain_part.contains('.') {
        return Err(AppError::BadRequest(msg::INVALID_EMAIL_FORMAT.into()));
    }

    // Domain cannot start or end with a dot
    if domain_part.starts_with('.') || domain_part.ends_with('.') {
        return Err(AppError::BadRequest(msg::INVALID_EMAIL_FORMAT.into()));
    }

    // Local part cannot have spaces
    if local_part.contains(' ') {
        return Err(AppError::BadRequest(msg::INVALID_EMAIL_FORMAT.into()));
    }

    Ok(())
}

/// User identity - source of truth for name/email
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    /// Operator role (None = not an operator)
    pub operator_role: Option<crate::models::OperatorRole>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub name: String,
}

impl CreateUser {
    pub fn validate(&self) -> Result<()> {
        validate_email_format(&self.email)?;
        if self.name.trim().is_empty() {
            return Err(AppError::BadRequest(msg::NAME_EMPTY.into()));
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
            validate_email_format(email)?;
        }
        if let Some(ref name) = self.name
            && name.trim().is_empty()
        {
            return Err(AppError::BadRequest(msg::NAME_EMPTY.into()));
        }
        Ok(())
    }
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
    pub operator_role: Option<crate::models::OperatorRole>,
    /// Org memberships
    pub memberships: Vec<UserOrgMembership>,
}
