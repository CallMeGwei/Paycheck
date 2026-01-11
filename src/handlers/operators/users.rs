use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::Deserialize;

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OperatorContext;
use crate::models::{ActorType, AuditAction, CreateUser, UpdateUser, UserWithRoles};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::AuditLogBuilder;

#[derive(Deserialize)]
pub struct UserQuery {
    #[serde(flatten)]
    pub pagination: PaginationQuery,
    /// Filter by email (exact match)
    pub email: Option<String>,
}

/// Create a new user.
pub async fn create_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Json(input): Json<CreateUser>,
) -> Result<Json<UserWithRoles>> {
    input.validate()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Check if email already exists
    if queries::get_user_by_email(&conn, &input.email)?.is_some() {
        return Err(AppError::BadRequest("Email already exists".into()));
    }

    let user = queries::create_user(&conn, &input)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::CreateUser)
        .resource("user", &user.id)
        .details(&serde_json::json!({
            "email": input.email,
            "name": input.name
        }))
        .names(&ctx.audit_names().resource(user.name.clone()))
        .save()?;

    // Return user with roles (will be empty for new user)
    let user_with_roles = queries::get_user_with_roles(&conn, &user.id)?
        .ok_or_else(|| AppError::Internal("Failed to fetch created user".into()))?;

    Ok(Json(user_with_roles))
}

/// List users with their roles.
pub async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<UserQuery>,
) -> Result<Json<Paginated<UserWithRoles>>> {
    let conn = state.db.get()?;

    // If email filter provided, return single result
    if let Some(email) = &query.email {
        let user = queries::get_user_by_email(&conn, email)?;
        if let Some(user) = user {
            let user_with_roles = queries::get_user_with_roles(&conn, &user.id)?
                .ok_or_else(|| AppError::Internal("Failed to fetch user".into()))?;
            return Ok(Json(Paginated::new(vec![user_with_roles], 1, 1, 0)));
        } else {
            return Ok(Json(Paginated::new(vec![], 0, 1, 0)));
        }
    }

    let limit = query.pagination.limit();
    let offset = query.pagination.offset();
    let (users, total) = queries::list_users_with_roles_paginated(&conn, limit, offset)?;

    Ok(Json(Paginated::new(users, total, limit, offset)))
}

/// Get a user by ID with their roles.
pub async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<UserWithRoles>> {
    let conn = state.db.get()?;
    let user = queries::get_user_with_roles(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;
    Ok(Json(user))
}

/// Update a user.
pub async fn update_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateUser>,
) -> Result<Json<UserWithRoles>> {
    input.validate()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_user_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    // If changing email, check it doesn't conflict
    if let Some(ref new_email) = input.email {
        if new_email != &existing.email {
            if queries::get_user_by_email(&conn, new_email)?.is_some() {
                return Err(AppError::BadRequest("Email already exists".into()));
            }
        }
    }

    queries::update_user(&conn, &id, &input)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::UpdateUser)
        .resource("user", &id)
        .details(&serde_json::json!({
            "email": input.email,
            "name": input.name
        }))
        .names(&ctx.audit_names().resource(existing.name.clone()))
        .save()?;

    let user = queries::get_user_with_roles(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    Ok(Json(user))
}

/// Delete a user.
/// This will cascade delete their operator record and org memberships.
pub async fn delete_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Don't allow deleting yourself
    if id == ctx.user.id {
        return Err(AppError::BadRequest("Cannot delete yourself".into()));
    }

    let existing = queries::get_user_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    queries::delete_user(&conn, &id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::DeleteUser)
        .resource("user", &id)
        .details(&serde_json::json!({
            "email": existing.email,
            "name": existing.name
        }))
        .names(&ctx.audit_names().resource(existing.name.clone()))
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}
