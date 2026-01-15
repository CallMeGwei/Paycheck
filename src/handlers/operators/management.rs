use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OperatorContext;
use crate::models::{
    ActorType, AuditAction, CreateOperator, Operator, OperatorWithUser, UpdateOperator,
};
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
        .names(&ctx.audit_names().resource_user(&user.name, &user.email))
        .auth_method(&ctx.auth_method)
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

/// Get an operator with user details by user_id
pub async fn get_operator(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<OperatorWithUser>> {
    let conn = state.db.get()?;
    let operator = queries::get_operator_with_user_by_user_id(&conn, &user_id)?
        .ok_or_else(|| AppError::NotFound("User is not an operator".into()))?;
    Ok(Json(operator))
}

pub async fn update_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(input): Json<UpdateOperator>,
) -> Result<Json<OperatorWithUser>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Prevent self-demotion
    if user_id == ctx.user.id && input.role.is_some() {
        return Err(AppError::BadRequest("Cannot change your own role".into()));
    }

    let existing = queries::get_operator_with_user_by_user_id(&conn, &user_id)?
        .ok_or_else(|| AppError::NotFound("User is not an operator".into()))?;

    queries::update_operator(&conn, &existing.id, &input)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::UpdateOperator)
        .resource("operator", &existing.id)
        .details(&serde_json::json!({ "role": input.role }))
        .names(
            &ctx.audit_names()
                .resource_user(&existing.name, &existing.email),
        )
        .auth_method(&ctx.auth_method)
        .save()?;

    let operator = queries::get_operator_with_user_by_user_id(&conn, &user_id)?
        .ok_or_else(|| AppError::NotFound("User is not an operator".into()))?;

    Ok(Json(operator))
}

pub async fn delete_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Prevent self-deletion
    if user_id == ctx.user.id {
        return Err(AppError::BadRequest("Cannot delete yourself".into()));
    }

    let existing = queries::get_operator_with_user_by_user_id(&conn, &user_id)?
        .ok_or_else(|| AppError::NotFound("User is not an operator".into()))?;

    queries::soft_delete_operator(&conn, &existing.id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::DeleteOperator)
        .resource("operator", &existing.id)
        .details(&serde_json::json!({
            "user_id": user_id,
            "email": existing.email
        }))
        .names(
            &ctx.audit_names()
                .resource_user(&existing.name, &existing.email),
        )
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}
