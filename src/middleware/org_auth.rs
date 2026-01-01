use std::collections::HashMap;

use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use crate::db::{queries, AppState};
use crate::models::{OrgMember, OrgMemberRole, ProjectMemberRole};
use crate::util::extract_bearer_token;

#[derive(Clone)]
pub struct OrgMemberContext {
    pub member: OrgMember,
    pub project_role: Option<ProjectMemberRole>,
}

impl OrgMemberContext {
    pub fn require_owner(&self) -> Result<(), StatusCode> {
        if self.member.role.can_manage_members() {
            Ok(())
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }

    pub fn require_admin(&self) -> Result<(), StatusCode> {
        if matches!(self.member.role, OrgMemberRole::Owner | OrgMemberRole::Admin) {
            Ok(())
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }

    pub fn can_write_project(&self) -> bool {
        matches!(self.member.role, OrgMemberRole::Owner | OrgMemberRole::Admin)
            || matches!(self.project_role, Some(ProjectMemberRole::Admin))
    }
}

pub async fn org_member_auth(
    State(state): State<AppState>,
    Path(params): Path<HashMap<String, String>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let org_id = params.get("org_id").ok_or(StatusCode::BAD_REQUEST)?;

    let api_key = extract_bearer_token(request.headers())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let conn = state.db.get().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let member = queries::get_org_member_by_api_key(&conn, api_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if member.org_id != *org_id {
        return Err(StatusCode::FORBIDDEN);
    }

    request.extensions_mut().insert(OrgMemberContext {
        member,
        project_role: None,
    });

    Ok(next.run(request).await)
}

/// Path struct for handlers that need org_id and project_id.
/// Note: The middleware uses HashMap extraction to support routes with extra params.
#[derive(Clone, serde::Deserialize)]
pub struct OrgProjectPath {
    pub org_id: String,
    pub project_id: String,
}

pub async fn org_member_project_auth(
    State(state): State<AppState>,
    Path(params): Path<HashMap<String, String>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let org_id = params.get("org_id").ok_or(StatusCode::BAD_REQUEST)?;
    let project_id = params.get("project_id").ok_or(StatusCode::BAD_REQUEST)?;

    let api_key = extract_bearer_token(request.headers())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let conn = state.db.get().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let member = queries::get_org_member_by_api_key(&conn, api_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if member.org_id != *org_id {
        return Err(StatusCode::FORBIDDEN);
    }

    // Check project exists and belongs to org
    let project = queries::get_project_by_id(&conn, project_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if project.org_id != *org_id {
        return Err(StatusCode::NOT_FOUND);
    }

    // Get project-level role if exists
    let project_role = if member.role.has_implicit_project_access() {
        None // Owner/admin have implicit access, no need for project_members entry
    } else {
        queries::get_project_member(&conn, &member.id, project_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .map(|pm| pm.role)
    };

    // Check if member has any access to this project
    if !member.role.has_implicit_project_access() && project_role.is_none() {
        return Err(StatusCode::FORBIDDEN);
    }

    request.extensions_mut().insert(OrgMemberContext {
        member,
        project_role,
    });

    Ok(next.run(request).await)
}
