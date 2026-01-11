use std::collections::HashMap;

use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use crate::db::{queries, AppState};
use crate::models::{
    AccessLevel, AuditLogNames, OrgMemberRole, OrgMemberWithUser, OperatorRole,
    ProjectMemberRole, User,
};
use crate::util::extract_bearer_token;

/// Header name for operator impersonation
const ON_BEHALF_OF_HEADER: &str = "x-on-behalf-of";

#[derive(Clone)]
pub struct OrgMemberContext {
    /// The org member (with user details joined)
    pub member: OrgMemberWithUser,
    /// The authenticated user (same as member's user unless impersonated)
    pub user: User,
    pub project_role: Option<ProjectMemberRole>,
    /// If set, this request is being made by an operator on behalf of the member
    pub impersonator: Option<ImpersonatorInfo>,
}

#[derive(Clone)]
pub struct ImpersonatorInfo {
    pub user_id: String,
    pub name: String,
    pub email: String,
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
        if matches!(
            self.member.role,
            OrgMemberRole::Owner | OrgMemberRole::Admin
        ) {
            Ok(())
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }

    pub fn can_write_project(&self) -> bool {
        matches!(
            self.member.role,
            OrgMemberRole::Owner | OrgMemberRole::Admin
        ) || matches!(self.project_role, Some(ProjectMemberRole::Admin))
    }

    /// Returns true if this request is being impersonated by an operator
    pub fn is_impersonated(&self) -> bool {
        self.impersonator.is_some()
    }

    /// Get audit log names pre-populated with the member's user info.
    /// Chain with `.resource()`, `.org()`, `.project()` to add more context.
    pub fn audit_names(&self) -> AuditLogNames {
        AuditLogNames {
            user_name: Some(self.member.name.clone()),
            user_email: Some(self.member.email.clone()),
            ..Default::default()
        }
    }
}

/// Attempt to authenticate as an operator impersonating an org member.
/// Returns Some((member_with_user, impersonator_info)) if impersonation is valid.
fn try_operator_impersonation(
    state: &AppState,
    user: &User,
    on_behalf_of: Option<&str>,
    org_id: &str,
) -> Result<Option<(OrgMemberWithUser, ImpersonatorInfo)>, StatusCode> {
    // Must have X-On-Behalf-Of header for impersonation
    let member_id = match on_behalf_of {
        Some(id) => id,
        None => return Ok(None), // No impersonation header - not an impersonation attempt
    };

    let conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Check if user is an operator with admin+ role
    let operator = queries::get_operator_by_user_id(&conn, &user.id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let operator = match operator {
        Some(op) => op,
        None => return Err(StatusCode::FORBIDDEN), // Has impersonation header but not an operator
    };

    // Only admin+ operators can impersonate
    if !matches!(operator.role, OperatorRole::Owner | OperatorRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Load the target org member with user details
    let member = queries::get_org_member_with_user_by_id(&conn, member_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Verify the member belongs to the specified org
    if member.org_id != org_id {
        return Err(StatusCode::FORBIDDEN);
    }

    let impersonator = ImpersonatorInfo {
        user_id: user.id.clone(),
        name: user.name.clone(),
        email: user.email.clone(),
    };

    Ok(Some((member, impersonator)))
}

/// Check if the API key has access to the specified org.
/// Returns Ok(()) if access is granted, Err if denied.
fn check_api_key_scope_for_org(
    state: &AppState,
    api_key: &str,
    org_id: &str,
    require_admin: bool,
) -> Result<(), StatusCode> {
    let conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Get the API key ID from the hash
    let hash = crate::crypto::hash_secret(api_key);
    let key_id: Option<String> = conn
        .query_row(
            "SELECT id FROM api_keys WHERE key_hash = ?1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > unixepoch())",
            rusqlite::params![&hash],
            |row| row.get(0),
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        .ok();

    let key_id = match key_id {
        Some(id) => id,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    // Check if the key has any scopes defined
    let has_scopes = queries::api_key_has_scopes(&conn, &key_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !has_scopes {
        // No scopes = full access (based on membership)
        return Ok(());
    }

    // Check if org is in scopes
    let required_access = if require_admin {
        AccessLevel::Admin
    } else {
        AccessLevel::View
    };

    let has_access =
        queries::check_api_key_scope(&conn, &key_id, org_id, None, required_access)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if has_access {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

pub async fn org_member_auth(
    State(state): State<AppState>,
    Path(params): Path<HashMap<String, String>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let org_id = params.get("org_id").ok_or(StatusCode::BAD_REQUEST)?;
    let api_key = extract_bearer_token(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    let on_behalf_of = request
        .headers()
        .get(ON_BEHALF_OF_HEADER)
        .and_then(|v| v.to_str().ok());

    let conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Get user by API key (returns (User, ApiKey) tuple)
    let (user, _api_key) = queries::get_user_by_api_key(&conn, api_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Try operator impersonation first
    if let Some((member, impersonator)) =
        try_operator_impersonation(&state, &user, on_behalf_of, org_id)?
    {
        request.extensions_mut().insert(OrgMemberContext {
            member,
            user,
            project_role: None,
            impersonator: Some(impersonator),
        });
        return Ok(next.run(request).await);
    }

    // Check API key scopes (if any)
    check_api_key_scope_for_org(&state, api_key, org_id, false)?;

    // Try normal org member authentication first
    let member = queries::get_org_member_with_user_by_user_and_org(&conn, &user.id, org_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(member) = member {
        // User is an org member
        request.extensions_mut().insert(OrgMemberContext {
            member,
            user,
            project_role: None,
            impersonator: None,
        });
        return Ok(next.run(request).await);
    }

    // Not an org member - check if they're an operator with admin+ role
    let operator = queries::get_operator_by_user_id(&conn, &user.id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(operator) = operator {
        if matches!(operator.role, OperatorRole::Owner | OperatorRole::Admin) {
            // Operator with admin+ role gets synthetic owner access
            let synthetic_member = OrgMemberWithUser {
                id: format!("operator:{}", operator.id),
                user_id: user.id.clone(),
                email: user.email.clone(),
                name: user.name.clone(),
                org_id: org_id.to_string(),
                role: OrgMemberRole::Owner, // Operators get owner-level access
                created_at: operator.created_at,
            };
            request.extensions_mut().insert(OrgMemberContext {
                member: synthetic_member,
                user,
                project_role: None,
                impersonator: None,
            });
            return Ok(next.run(request).await);
        }
    }

    // Not an org member and not an admin+ operator
    Err(StatusCode::FORBIDDEN)
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
    let api_key = extract_bearer_token(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    let on_behalf_of = request
        .headers()
        .get(ON_BEHALF_OF_HEADER)
        .and_then(|v| v.to_str().ok());

    let conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Get user by API key (returns (User, ApiKey) tuple)
    let (user, _api_key) = queries::get_user_by_api_key(&conn, api_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Try operator impersonation first
    let (member, impersonator) =
        if let Some((member, impersonator)) =
            try_operator_impersonation(&state, &user, on_behalf_of, org_id)?
        {
            (member, Some(impersonator))
        } else {
            // Check API key scopes (if any)
            check_api_key_scope_for_org(&state, api_key, org_id, false)?;

            // Try normal org member authentication
            let member =
                queries::get_org_member_with_user_by_user_and_org(&conn, &user.id, org_id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            if let Some(member) = member {
                (member, None)
            } else {
                // Not an org member - check if they're an operator with admin+ role
                let operator = queries::get_operator_by_user_id(&conn, &user.id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                if let Some(operator) = operator {
                    if matches!(operator.role, OperatorRole::Owner | OperatorRole::Admin) {
                        // Operator with admin+ role gets synthetic owner access
                        let synthetic_member = OrgMemberWithUser {
                            id: format!("operator:{}", operator.id),
                            user_id: user.id.clone(),
                            email: user.email.clone(),
                            name: user.name.clone(),
                            org_id: org_id.to_string(),
                            role: OrgMemberRole::Owner,
                            created_at: operator.created_at,
                        };
                        (synthetic_member, None)
                    } else {
                        return Err(StatusCode::FORBIDDEN);
                    }
                } else {
                    return Err(StatusCode::FORBIDDEN);
                }
            }
        };

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
    // Return 404 (not 403) to avoid leaking project existence to unauthorized users
    if !member.role.has_implicit_project_access() && project_role.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    request.extensions_mut().insert(OrgMemberContext {
        member,
        user,
        project_role,
        impersonator,
    });

    Ok(next.run(request).await)
}
