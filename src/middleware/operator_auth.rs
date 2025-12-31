use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use crate::db::{queries, AppState};
use crate::models::{Operator, OperatorRole};
use crate::util::extract_bearer_token;

#[derive(Clone)]
pub struct OperatorContext {
    pub operator: Operator,
}


pub async fn operator_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let api_key = extract_bearer_token(request.headers())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let conn = state.db.get().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let operator = queries::get_operator_by_api_key(&conn, api_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    request.extensions_mut().insert(OperatorContext { operator });

    Ok(next.run(request).await)
}

pub async fn require_owner_role(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let api_key = extract_bearer_token(request.headers())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let conn = state.db.get().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let operator = queries::get_operator_by_api_key(&conn, api_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !matches!(operator.role, OperatorRole::Owner) {
        return Err(StatusCode::FORBIDDEN);
    }

    request.extensions_mut().insert(OperatorContext { operator });

    Ok(next.run(request).await)
}

pub async fn require_admin_role(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let api_key = extract_bearer_token(request.headers())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let conn = state.db.get().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let operator = queries::get_operator_by_api_key(&conn, api_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !matches!(operator.role, OperatorRole::Owner | OperatorRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    request.extensions_mut().insert(OperatorContext { operator });

    Ok(next.run(request).await)
}
