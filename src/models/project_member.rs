use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsRefStr, EnumString)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum ProjectMemberRole {
    Admin,
    View,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMember {
    pub id: String,
    pub org_member_id: String,
    pub project_id: String,
    pub role: ProjectMemberRole,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectMemberWithDetails {
    pub id: String,
    pub org_member_id: String,
    pub project_id: String,
    pub role: ProjectMemberRole,
    pub created_at: i64,
    pub email: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateProjectMember {
    pub org_member_id: String,
    pub role: ProjectMemberRole,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProjectMember {
    pub role: ProjectMemberRole,
}
