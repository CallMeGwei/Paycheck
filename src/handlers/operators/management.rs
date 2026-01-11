use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OperatorContext;
use crate::models::{ActorType, AuditAction, CreateOperator, Operator, OperatorWithUser, UpdateOperator};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::AuditLogBuilder;

/// Create an operator (link a user to operator role).
/// The user must already exist in the users table.
/// No API key is created - use Console or create one separately.
pub async fn create_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Json(input): Json<CreateOperator>,
) -> Result<Json<Operator>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify the user exists
    let user = queries::get_user_by_id(&conn, &input.user_id)?
        .ok_or_else(|| AppError::BadRequest("User not found".into()))?;

    let operator = queries::create_operator(&conn, &input)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::CreateOperator)
        .resource("operator", &operator.id)
        .details(&serde_json::json!({
            "user_id": input.user_id,
            "email": user.email,
            "role": input.role
        }))
        .names(&ctx.audit_names().resource(user.name.clone()))
        .save()?;

    Ok(Json(operator))
}

/// List operators with user details
pub async fn list_operators(
    State(state): State<AppState>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Paginated<OperatorWithUser>>> {
    let conn = state.db.get()?;
    let limit = pagination.limit();
    let offset = pagination.offset();
    let (operators, total) = queries::list_operators_paginated(&conn, limit, offset)?;
    Ok(Json(Paginated::new(operators, total, limit, offset)))
}

/// Get an operator with user details
pub async fn get_operator(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<OperatorWithUser>> {
    let conn = state.db.get()?;
    let operator = queries::get_operator_with_user_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;
    Ok(Json(operator))
}

pub async fn update_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateOperator>,
) -> Result<Json<OperatorWithUser>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Prevent self-demotion
    if id == ctx.operator.id && input.role.is_some() {
        return Err(AppError::BadRequest("Cannot change your own role".into()));
    }

    let existing = queries::get_operator_with_user_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;

    queries::update_operator(&conn, &id, &input)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::UpdateOperator)
        .resource("operator", &id)
        .details(&serde_json::json!({ "role": input.role }))
        .names(&ctx.audit_names().resource(existing.name.clone()))
        .save()?;

    let operator = queries::get_operator_with_user_by_id(&conn, &id)?
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

    let existing = queries::get_operator_with_user_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;

    queries::delete_operator(&conn, &id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::DeleteOperator)
        .resource("operator", &id)
        .details(&serde_json::json!({
            "user_id": existing.user_id,
            "email": existing.email
        }))
        .names(&ctx.audit_names().resource(existing.name.clone()))
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}
