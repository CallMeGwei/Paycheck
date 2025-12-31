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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMember {
    pub id: String,
    pub org_id: String,
    pub email: String,
    pub name: String,
    pub role: OrgMemberRole,
    #[serde(skip_serializing)]
    pub api_key_hash: String,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrgMember {
    pub email: String,
    pub name: String,
    pub role: OrgMemberRole,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrgMember {
    pub name: Option<String>,
    pub role: Option<OrgMemberRole>,
}
