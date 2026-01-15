use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::Deserialize;

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OperatorContext;
use crate::models::{ActorType, ApiKeyCreated, ApiKeyInfo, AuditAction, CreateApiKey};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::AuditLogBuilder;

#[derive(Deserialize)]
pub struct UserApiKeyPath {
    pub user_id: String,
}

#[derive(Deserialize)]
pub struct UserApiKeyIdPath {
    pub user_id: String,
    pub key_id: String,
}

/// Create a new API key for a user.
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    Path(path): Path<UserApiKeyPath>,
    headers: HeaderMap,
    Json(input): Json<CreateApiKey>,
) -> Result<Json<ApiKeyCreated>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify the target user exists
    let target_user = queries::get_user_by_id(&conn, &path.user_id)?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    // Create API key for the user
    let user_manageable = input.user_manageable.unwrap_or(true);
    let (key_record, full_key) = queries::create_api_key(
        &conn,
        &path.user_id,
        &input.name,
        input.expires_in_days,
        user_manageable,
        input.scopes.as_deref(),
    )?;

    // Get scopes from the created key
    let scopes = if input.scopes.is_some() {
        Some(queries::get_api_key_scopes(&conn, &key_record.id)?)
    } else {
        None
    };

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::CreateApiKey)
        .resource("api_key", &key_record.id)
        .details(&serde_json::json!({
            "target_user_id": path.user_id,
            "target_email": target_user.email,
            "name": input.name
        }))
        .names(
            &ctx.audit_names()
                .resource_user(&target_user.name, &target_user.email)
                .resource(input.name.clone()),
        )
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(ApiKeyCreated {
        id: key_record.id,
        name: key_record.name,
        key: full_key,
        prefix: key_record.prefix,
        user_manageable: key_record.user_manageable,
        created_at: key_record.created_at,
        expires_at: key_record.expires_at,
        scopes,
    }))
}

/// List API keys for a user
pub async fn list_api_keys(
    State(state): State<AppState>,
    Path(path): Path<UserApiKeyPath>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<Paginated<ApiKeyInfo>>> {
    let conn = state.db.get()?;

    // Verify the target user exists
    let _target_user = queries::get_user_by_id(&conn, &path.user_id)?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    let limit = query.limit();
    let offset = query.offset();
    // Operators can see all keys (not just user-manageable ones)
    let (keys, total) =
        queries::list_api_keys_paginated(&conn, &path.user_id, false, limit, offset)?;

    // Batch load scopes (single query instead of N+1)
    let key_ids: Vec<String> = keys.iter().map(|k| k.id.clone()).collect();
    let scopes_map = queries::get_api_key_scopes_batch(&conn, &key_ids)?;

    // Convert to ApiKeyInfo with scopes
    let items: Vec<ApiKeyInfo> = keys
        .into_iter()
        .map(|key| {
            let scopes = scopes_map.get(&key.id).cloned();
            let mut info: ApiKeyInfo = key.into();
            info.scopes = scopes.filter(|s| !s.is_empty());
            info
        })
        .collect();

    Ok(Json(Paginated::new(items, total, limit, offset)))
}

/// Revoke a specific API key
pub async fn revoke_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    Path(path): Path<UserApiKeyIdPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify the target user exists
    let target_user = queries::get_user_by_id(&conn, &path.user_id)?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    // Verify key exists and belongs to the right user
    let key = queries::get_api_key_by_id(&conn, &path.key_id)?
        .ok_or_else(|| AppError::NotFound("API key not found".into()))?;

    if key.user_id != path.user_id {
        return Err(AppError::NotFound("API key not found".into()));
    }

    queries::revoke_api_key(&conn, &path.key_id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::RevokeApiKey)
        .resource("api_key", &path.key_id)
        .details(&serde_json::json!({
            "target_user_id": path.user_id,
            "target_email": target_user.email,
            "key_name": key.name
        }))
        .names(
            &ctx.audit_names()
                .resource_user(&target_user.name, &target_user.email)
                .resource(key.name.clone()),
        )
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}
