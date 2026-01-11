use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::db::{queries, AppState};
use crate::models::{AuditLogNames, OperatorRole, OperatorWithUser, User};
use crate::util::extract_bearer_token;

#[derive(Clone)]
pub struct OperatorContext {
    pub operator: OperatorWithUser,
    pub user: User,
}

impl OperatorContext {
    /// Get audit log names pre-populated with the user's name and email.
    /// Chain with `.resource()`, `.org()`, `.project()` to add more context.
    pub fn audit_names(&self) -> AuditLogNames {
        AuditLogNames {
            user_name: Some(self.user.name.clone()),
            user_email: Some(self.user.email.clone()),
            ..Default::default()
        }
    }
}

/// Authenticate operator from bearer token.
/// Returns (OperatorWithUser, User) if authentication succeeds.
fn authenticate_operator(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(OperatorWithUser, User), StatusCode> {
    let api_key = extract_bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Get user by API key (returns (User, ApiKey) tuple)
    let (user, _api_key) = queries::get_user_by_api_key(&conn, api_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if user is an operator
    let operator = queries::get_operator_with_user_by_user_id(&conn, &user.id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok((operator, user))
}

pub async fn operator_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (operator, user) = authenticate_operator(&state, request.headers())?;
    request
        .extensions_mut()
        .insert(OperatorContext { operator, user });
    Ok(next.run(request).await)
}

pub async fn require_owner_role(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (operator, user) = authenticate_operator(&state, request.headers())?;
    if !matches!(operator.role, OperatorRole::Owner) {
        return Err(StatusCode::FORBIDDEN);
    }
    request
        .extensions_mut()
        .insert(OperatorContext { operator, user });
    Ok(next.run(request).await)
}

pub async fn require_admin_role(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (operator, user) = authenticate_operator(&state, request.headers())?;
    if !matches!(operator.role, OperatorRole::Owner | OperatorRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }
    request
        .extensions_mut()
        .insert(OperatorContext { operator, user });
    Ok(next.run(request).await)
}
