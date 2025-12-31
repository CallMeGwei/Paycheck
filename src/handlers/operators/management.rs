use axum::{
    extract::{Extension, Path, State},
    http::HeaderMap,
    Json,
};
use serde::Serialize;

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::middleware::OperatorContext;
use crate::models::{ActorType, CreateOperator, Operator, UpdateOperator};

#[derive(Serialize)]
pub struct OperatorCreated {
    pub operator: Operator,
    pub api_key: String,
}

fn extract_request_info(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    (ip, user_agent)
}

pub async fn create_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Json(input): Json<CreateOperator>,
) -> Result<Json<OperatorCreated>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;
    let api_key = queries::generate_api_key();
    let operator = queries::create_operator(&conn, &input, &api_key, Some(&ctx.operator.id))?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        ActorType::Operator,
        Some(&ctx.operator.id),
        "create_operator",
        "operator",
        &operator.id,
        Some(&serde_json::json!({
            "email": input.email,
            "role": input.role,
        })),
        None,
        None,
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(OperatorCreated { operator, api_key }))
}

pub async fn list_operators(State(state): State<AppState>) -> Result<Json<Vec<Operator>>> {
    let conn = state.db.get()?;
    let operators = queries::list_operators(&conn)?;
    Ok(Json(operators))
}

pub async fn get_operator(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Operator>> {
    let conn = state.db.get()?;
    let operator = queries::get_operator_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;
    Ok(Json(operator))
}

pub async fn update_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateOperator>,
) -> Result<Json<Operator>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Prevent self-demotion
    if id == ctx.operator.id && input.role.is_some() {
        return Err(AppError::BadRequest(
            "Cannot change your own role".into(),
        ));
    }

    let _existing = queries::get_operator_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;

    queries::update_operator(&conn, &id, &input)?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        ActorType::Operator,
        Some(&ctx.operator.id),
        "update_operator",
        "operator",
        &id,
        Some(&serde_json::json!({
            "name": input.name,
            "role": input.role,
        })),
        None,
        None,
        ip.as_deref(),
        ua.as_deref(),
    )?;

    let operator = queries::get_operator_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;

    Ok(Json(operator))
}

pub async fn delete_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Prevent self-deletion
    if id == ctx.operator.id {
        return Err(AppError::BadRequest("Cannot delete yourself".into()));
    }

    let existing = queries::get_operator_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;

    queries::delete_operator(&conn, &id)?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        ActorType::Operator,
        Some(&ctx.operator.id),
        "delete_operator",
        "operator",
        &id,
        Some(&serde_json::json!({
            "email": existing.email,
        })),
        None,
        None,
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
