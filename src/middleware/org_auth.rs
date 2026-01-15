//! Organization member authentication middleware.
//!
//! This module implements a **three-path authentication system** for org-level
//! endpoints (`/orgs/{org_id}/*`). Requests are authenticated in priority order:
//!
//! # Authentication Paths
//!
//! ## Path 1: Operator Impersonation (Highest Priority)
//!
//! **Trigger:** `X-On-Behalf-Of: {target_user_id}` header present
//!
//! - User must be an `admin+` operator (owner or admin role)
//! - Target user must be a member of the specified org
//! - Request executes with **target member's actual role** in that org
//! - Useful for: Admin support, testing member workflows, member-initiated actions
//!
//! **Audit trail:** Includes explicit `impersonator` details in JSON:
//! ```json
//! {
//!   "impersonator": {"user_id": "op123", "email": "admin@example.com"}
//! }
//! ```
//! The `user_id` in the audit log is the **impersonator's** ID, not the target's.
//!
//! **Errors:**
//! - `403 Forbidden`: Header present but user is not an admin+ operator
//! - `404 Not Found`: Target user is not a member of the specified org
//!
//! ## Path 2: Normal Org Member Authentication
//!
//! **Trigger:** No `X-On-Behalf-Of` header, user is an org member
//!
//! - User's org membership is validated via `org_members` table
//! - Request executes with user's **actual role** in that org
//! - API key scopes are checked if applicable
//! - Most common path for regular org operations
//!
//! **Audit trail:** No impersonation details; shows authenticated user's info.
//!
//! **Errors:**
//! - `403 Forbidden`: API key lacks required scope for org
//! - Continues to Path 3 if user is not an org member
//!
//! ## Path 3: Synthetic Operator Direct Access
//!
//! **Trigger:** User is NOT an org member, but IS an admin+ operator
//!
//! - User must be an `admin+` operator (owner or admin role)
//! - A synthetic `OrgMemberWithUser` is created with `Owner` role
//! - Synthetic member ID format: `operator:{operator.id}`
//! - Request executes with **owner-level access** to all org operations
//! - Useful for: Admin support/troubleshooting, operator dashboard access
//!
//! **Audit trail:** No indication this is synthetic access (by design—support
//! operations appear normal in logs).
//!
//! **Errors:**
//! - `403 Forbidden`: User is an operator but role is less than admin
//! - `403 Forbidden`: User is neither an org member nor an admin+ operator
//!
//! # Security Properties
//!
//! - **Path precedence:** Impersonation is checked first, preventing accidental
//!   fallthrough to synthetic access
//! - **Role requirements:** Impersonation and synthetic access require admin+ role
//! - **404 not 403:** Non-member lookups return 404, preventing org enumeration
//! - **API key scopes:** Checked only for normal member auth (Path 2)
//! - **Audit logs record the acting user**, enabling traceability of all actions
//!
//! # Project-Level Authentication
//!
//! The `org_member_project_auth` middleware extends the three-path system with:
//! - Project existence and ownership validation
//! - Project-level role resolution (for `Member` org role users)
//! - Owner/Admin org members get implicit project access
//! - `Member` role users need explicit `project_members` entries
//!
//! # Usage
//!
//! ```ignore
//! // Org-level routes (members, projects, audit logs)
//! Router::new()
//!     .route("/orgs/:org_id/members", get(list_members))
//!     .layer(middleware::from_fn_with_state(state.clone(), org_member_auth))
//!
//! // Project-level routes (products, licenses)
//! Router::new()
//!     .route("/orgs/:org_id/projects/:project_id/products", get(list_products))
//!     .layer(middleware::from_fn_with_state(state.clone(), org_member_project_auth))
//! ```

use std::collections::HashMap;

use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use crate::db::{AppState, queries};
use crate::jwt::validate_first_party_token;
use crate::models::{
    AccessLevel, AuditLogNames, OperatorRole, OrgMemberRole, OrgMemberWithUser, ProjectMemberRole,
    User,
};
use crate::util::extract_bearer_token;

use super::AuthMethod;

/// Header name for operator impersonation.
/// Value should be a `user_id` (not member_id).
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
    /// How the request was authenticated (API key or JWT)
    pub auth_method: AuthMethod,
    /// API key access level (None for JWT auth, Some for scoped API key auth)
    pub api_key_access: Option<AccessLevel>,
}

#[derive(Clone)]
pub struct ImpersonatorInfo {
    pub user_id: String,
    pub name: String,
    pub email: String,
}

impl OrgMemberContext {
    pub fn require_owner(&self) -> Result<(), StatusCode> {
        // Check API key access level first - View-only keys cannot write
        if let Some(AccessLevel::View) = self.api_key_access {
            return Err(StatusCode::FORBIDDEN);
        }

        if self.member.role.can_manage_members() {
            Ok(())
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }

    pub fn require_admin(&self) -> Result<(), StatusCode> {
        // Check API key access level first - View-only keys cannot write
        if let Some(AccessLevel::View) = self.api_key_access {
            return Err(StatusCode::FORBIDDEN);
        }

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
        // Check API key access level first - View-only keys cannot write
        if let Some(AccessLevel::View) = self.api_key_access {
            return false;
        }

        // Then check role-based permissions
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
    // Must have X-On-Behalf-Of header for impersonation (takes user_id)
    let target_user_id = match on_behalf_of {
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

    // Load the target org member by user_id and org_id
    let member = queries::get_org_member_with_user_by_user_and_org(&conn, target_user_id, org_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let impersonator = ImpersonatorInfo {
        user_id: user.id.clone(),
        name: user.name.clone(),
        email: user.email.clone(),
    };

    Ok(Some((member, impersonator)))
}

/// Check if the API key has access to the specified org (and optionally project).
/// Returns Ok(Some(AccessLevel)) if access is granted via scopes.
/// Returns Ok(None) if the key has no scopes (full access based on membership).
/// Returns Err if access is denied.
///
/// For org-level endpoints (project_id is None), only org-level scopes are accepted.
/// Project-scoped keys cannot access org-level endpoints.
///
/// For project-level endpoints (project_id is Some), both project-specific and
/// org-level scopes are accepted (org-level implies access to all projects).
fn check_api_key_scope_for_org(
    state: &AppState,
    api_key: &str,
    org_id: &str,
    project_id: Option<&str>,
) -> Result<Option<AccessLevel>, StatusCode> {
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
        return Ok(None);
    }

    // Get access level based on whether this is org-level or project-level endpoint
    let access_level = if let Some(proj_id) = project_id {
        // Project-level endpoint: accept project-specific OR org-level scopes
        queries::get_api_key_access_level(&conn, &key_id, org_id, Some(proj_id))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        // Org-level endpoint: ONLY accept org-level scopes (not project-specific)
        queries::get_api_key_org_level_access(&conn, &key_id, org_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    match access_level {
        Some(level) => Ok(Some(level)),
        None => Err(StatusCode::FORBIDDEN),
    }
}

/// Authenticate user from JWT token.
/// Returns (User, AuthMethod) if authentication succeeds.
async fn authenticate_user_jwt(
    state: &AppState,
    token: &str,
) -> Result<(User, AuthMethod), StatusCode> {
    // Validate the JWT
    let validated = validate_first_party_token(token, &state.trusted_issuers, &state.jwks_cache)
        .await
        .map_err(|e| {
            tracing::debug!("JWT validation failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    let conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Look up user by email
    let user = queries::get_user_by_email(&conn, &validated.claims.email)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let auth_method = AuthMethod::Jwt {
        issuer: validated.issuer,
    };

    Ok((user, auth_method))
}

/// Middleware for org-level endpoints (`/orgs/{org_id}/*`).
///
/// Implements the three-path authentication system documented at module level.
/// Inserts an `OrgMemberContext` into request extensions on success.
///
/// # Authentication Flow
///
/// 1. Extract bearer token and optional `X-On-Behalf-Of` header
/// 2. Authenticate user via JWT or API key
/// 3. **Path 1:** Try operator impersonation (if header present)
/// 4. **Path 2:** Try normal org member authentication
/// 5. **Path 3:** Try synthetic operator access (admin+ operators)
/// 6. Return 403 if none of the above paths succeed
///
/// # Request Extensions
///
/// On success, inserts `OrgMemberContext` containing:
/// - `member`: The org member (real or synthetic)
/// - `user`: The authenticated user
/// - `impersonator`: Set only for Path 1 (impersonation)
/// - `auth_method`: How the request was authenticated
pub async fn org_member_auth(
    State(state): State<AppState>,
    Path(params): Path<HashMap<String, String>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let org_id = params.get("org_id").ok_or(StatusCode::BAD_REQUEST)?;
    let token = extract_bearer_token(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    let on_behalf_of = request
        .headers()
        .get(ON_BEHALF_OF_HEADER)
        .and_then(|v| v.to_str().ok());

    // Authenticate user - either via JWT or API key
    let (user, auth_method, api_key_record) = if token.starts_with("eyJ") {
        // JWT authentication
        let (user, auth_method) = authenticate_user_jwt(&state, token).await?;
        (user, auth_method, None)
    } else {
        // API key authentication
        let conn = state
            .db
            .get()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let (user, api_key_record) = queries::get_user_by_api_key(&conn, token)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let auth_method = AuthMethod::ApiKey {
            key_id: api_key_record.id.clone(),
            key_prefix: api_key_record.prefix.clone(),
        };
        (user, auth_method, Some(api_key_record))
    };

    let conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Try operator impersonation first
    if let Some((member, impersonator)) =
        try_operator_impersonation(&state, &user, on_behalf_of, org_id)?
    {
        request.extensions_mut().insert(OrgMemberContext {
            member,
            user,
            project_role: None,
            impersonator: Some(impersonator),
            auth_method,
            api_key_access: None, // Operators bypass scope checks
        });
        return Ok(next.run(request).await);
    }

    // Check API key scopes (if any) - only for API key auth
    // For org-level endpoints, only org-level scopes are accepted (project-scoped keys are rejected)
    let api_key_access = if api_key_record.is_some() {
        check_api_key_scope_for_org(&state, token, org_id, None)?
    } else {
        None
    };

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
            auth_method,
            api_key_access,
        });
        return Ok(next.run(request).await);
    }

    // Not an org member - check if they're an operator with admin+ role
    let operator = queries::get_operator_by_user_id(&conn, &user.id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(operator) = operator
        && matches!(operator.role, OperatorRole::Owner | OperatorRole::Admin)
    {
        // Operator with admin+ role gets synthetic owner access
        let synthetic_member = OrgMemberWithUser {
            id: format!("operator:{}", operator.id),
            user_id: user.id.clone(),
            email: user.email.clone(),
            name: user.name.clone(),
            org_id: org_id.to_string(),
            role: OrgMemberRole::Owner, // Operators get owner-level access
            created_at: operator.created_at,
            deleted_at: None,
            deleted_cascade_depth: None,
        };
        request.extensions_mut().insert(OrgMemberContext {
            member: synthetic_member,
            user,
            project_role: None,
            impersonator: None,
            auth_method,
            api_key_access: None, // Operators bypass scope checks
        });
        return Ok(next.run(request).await);
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

/// Middleware for project-level endpoints (`/orgs/{org_id}/projects/{project_id}/*`).
///
/// Extends `org_member_auth` with project-level access checks. Uses the same
/// three-path authentication system, then validates project access.
///
/// # Additional Checks
///
/// After org authentication succeeds, this middleware:
/// 1. Validates the project exists and belongs to the org
/// 2. Resolves project-level role:
///    - **Owner/Admin** org members: Implicit access (no project member entry needed)
///    - **Member** org role: Must have explicit `project_members` entry
/// 3. Returns 404 if user has no access (prevents project enumeration)
///
/// # Request Extensions
///
/// On success, inserts `OrgMemberContext` with `project_role` populated:
/// - `Some(ProjectMemberRole::Admin)`: Can modify project (update, manage products/licenses)
/// - `Some(ProjectMemberRole::View)`: Read-only access
/// - `None`: Owner/Admin org members (implicit full access)
///
/// Handlers should use `ctx.can_write_project()` to check write access, which
/// returns true for Owner/Admin org members OR ProjectMemberRole::Admin.
pub async fn org_member_project_auth(
    State(state): State<AppState>,
    Path(params): Path<HashMap<String, String>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let org_id = params.get("org_id").ok_or(StatusCode::BAD_REQUEST)?;
    let project_id = params.get("project_id").ok_or(StatusCode::BAD_REQUEST)?;
    let token = extract_bearer_token(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    let on_behalf_of = request
        .headers()
        .get(ON_BEHALF_OF_HEADER)
        .and_then(|v| v.to_str().ok());

    // Authenticate user - either via JWT or API key
    let (user, auth_method, is_api_key) = if token.starts_with("eyJ") {
        // JWT authentication
        let (user, auth_method) = authenticate_user_jwt(&state, token).await?;
        (user, auth_method, false)
    } else {
        // API key authentication
        let conn = state
            .db
            .get()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let (user, api_key_record) = queries::get_user_by_api_key(&conn, token)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let auth_method = AuthMethod::ApiKey {
            key_id: api_key_record.id,
            key_prefix: api_key_record.prefix,
        };
        (user, auth_method, true)
    };

    let conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Try operator impersonation first
    let (member, impersonator, api_key_access) = if let Some((member, impersonator)) =
        try_operator_impersonation(&state, &user, on_behalf_of, org_id)?
    {
        (member, Some(impersonator), None) // Operators bypass scope checks
    } else {
        // Check API key scopes (if any) - only for API key auth
        // For project-level endpoints, pass project_id to enforce project-level scope checking
        let api_key_access = if is_api_key {
            check_api_key_scope_for_org(&state, token, org_id, Some(project_id))?
        } else {
            None
        };

        // Try normal org member authentication
        let member = queries::get_org_member_with_user_by_user_and_org(&conn, &user.id, org_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        if let Some(member) = member {
            (member, None, api_key_access)
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
                        deleted_at: None,
                        deleted_cascade_depth: None,
                    };
                    (synthetic_member, None, None) // Operators bypass scope checks
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
        auth_method,
        api_key_access,
    });

    Ok(next.run(request).await)
}
