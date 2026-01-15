use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::db::{AppState, queries};
use crate::jwt::validate_first_party_token;
use crate::models::{AuditLogNames, OperatorRole, OperatorWithUser, User};
use crate::util::extract_bearer_token;

use super::AuthMethod;

#[derive(Clone)]
pub struct OperatorContext {
    pub operator: OperatorWithUser,
    pub user: User,
    /// How the request was authenticated (API key or JWT)
    pub auth_method: AuthMethod,
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

/// Authenticate operator from bearer token (API key or JWT).
/// Returns (OperatorWithUser, User, AuthMethod) if authentication succeeds.
fn authenticate_operator(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(OperatorWithUser, User, AuthMethod), StatusCode> {
    let token = extract_bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Determine auth method based on token format
    if token.starts_with("eyJ") {
        // JWT token - needs async validation, delegate to async function
        // We can't await in a sync context, so we'll handle this differently
        // For now, return an error - the async path will be handled separately
        return Err(StatusCode::UNAUTHORIZED);
    }

    // API key path (default)
    // Get user by API key (returns (User, ApiKey) tuple)
    let (user, api_key_record) = queries::get_user_by_api_key(&conn, token)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if user is an operator
    let operator = queries::get_operator_with_user_by_user_id(&conn, &user.id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let auth_method = AuthMethod::ApiKey {
        key_id: api_key_record.id,
        key_prefix: api_key_record.prefix,
    };

    Ok((operator, user, auth_method))
}

/// Authenticate operator from JWT token.
/// Returns (OperatorWithUser, User, AuthMethod) if authentication succeeds.
async fn authenticate_operator_jwt(
    state: &AppState,
    token: &str,
) -> Result<(OperatorWithUser, User, AuthMethod), StatusCode> {
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

    // Check if user is an operator
    let operator = queries::get_operator_with_user_by_user_id(&conn, &user.id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let auth_method = AuthMethod::Jwt {
        issuer: validated.issuer,
    };

    Ok((operator, user, auth_method))
}

/// Authenticate operator from request headers (API key or JWT).
async fn authenticate_from_request(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(OperatorWithUser, User, AuthMethod), StatusCode> {
    let token = extract_bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;

    if token.starts_with("eyJ") {
        authenticate_operator_jwt(state, token).await
    } else {
        authenticate_operator(state, headers)
    }
}

pub async fn operator_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (operator, user, auth_method) =
        authenticate_from_request(&state, request.headers()).await?;

    request.extensions_mut().insert(OperatorContext {
        operator,
        user,
        auth_method,
    });
    Ok(next.run(request).await)
}

pub async fn require_owner_role(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (operator, user, auth_method) =
        authenticate_from_request(&state, request.headers()).await?;

    if !matches!(operator.role, OperatorRole::Owner) {
        return Err(StatusCode::FORBIDDEN);
    }

    request.extensions_mut().insert(OperatorContext {
        operator,
        user,
        auth_method,
    });
    Ok(next.run(request).await)
}

pub async fn require_admin_role(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (operator, user, auth_method) =
        authenticate_from_request(&state, request.headers()).await?;

    if !matches!(operator.role, OperatorRole::Owner | OperatorRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    request.extensions_mut().insert(OperatorContext {
        operator,
        user,
        auth_method,
    });
    Ok(next.run(request).await)
}
