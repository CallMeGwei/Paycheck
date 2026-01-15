use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsRefStr, EnumString)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum OrgMemberRole {
    Owner,
    Admin,
    Member,
}

impl OrgMemberRole {
    pub fn can_manage_members(&self) -> bool {
        matches!(self, OrgMemberRole::Owner)
    }

    pub fn has_implicit_project_access(&self) -> bool {
        matches!(self, OrgMemberRole::Owner | OrgMemberRole::Admin)
    }
}

/// Org member record - links a user to an org with a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMember {
    pub id: String,
    pub user_id: String,
    pub org_id: String,
    pub role: OrgMemberRole,
    pub created_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

/// Org member with user info joined (for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMemberWithUser {
    /// Internal ID - not exposed in API responses (use user_id instead)
    #[serde(skip_serializing)]
    pub id: String,
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub org_id: String,
    pub role: OrgMemberRole,
    pub created_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrgMember {
    pub user_id: String,
    pub role: OrgMemberRole,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrgMember {
    pub role: Option<OrgMemberRole>,
}
