use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::Deserialize;

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, ApiKeyCreated, ApiKeyInfo, AuditAction, CreateApiKey};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::AuditLogBuilder;

#[derive(Deserialize)]
pub struct MemberApiKeyPath {
    pub org_id: String,
    pub user_id: String,
}

#[derive(Deserialize)]
pub struct MemberApiKeyIdPath {
    pub org_id: String,
    pub user_id: String,
    pub key_id: String,
}

/// Create a new API key for an org member.
/// The key is created for the member's user identity.
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<MemberApiKeyPath>,
    headers: HeaderMap,
    Json(input): Json<CreateApiKey>,
) -> Result<Json<ApiKeyCreated>> {
    // Only owner can manage other members' keys, or member can manage their own
    if path.user_id != ctx.member.user_id {
        ctx.require_owner()?;
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Get the target member with user details
    let target_member =
        queries::get_org_member_with_user_by_user_and_org(&conn, &path.user_id, &path.org_id)?
            .ok_or_else(|| AppError::NotFound("User is not a member of this org".into()))?;

    // Validate that all scopes are for the current org (security boundary)
    // Users should only be able to create scopes for orgs they're managing keys within
    if let Some(ref scopes) = input.scopes {
        for scope in scopes {
            if scope.org_id != path.org_id {
                return Err(AppError::BadRequest(
                    "Invalid scope: org_id must match the current organization".into(),
                ));
            }
        }
    }

    // Create API key for the member's user identity
    // Note: org member keys default to user_manageable=true unless explicitly set
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
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::CreateApiKey)
        .resource("api_key", &key_record.id)
        .details(&serde_json::json!({
            "target_user_id": path.user_id,
            "target_email": target_member.email,
            "name": input.name,
            "impersonator": ctx.impersonator.as_ref().map(|i| serde_json::json!({
                "user_id": i.user_id,
                "email": i.email
            }))
        }))
        .org(&path.org_id)
        .names(&ctx.audit_names().resource(key_record.name.clone()))
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

/// List API keys for an org member's user identity
pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<MemberApiKeyPath>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<Paginated<ApiKeyInfo>>> {
    // Only owner can see other members' keys, or member can see their own
    if path.user_id != ctx.member.user_id {
        ctx.require_owner()?;
    }

    let conn = state.db.get()?;

    // Verify the user is a member of this org
    let _target_member =
        queries::get_org_member_with_user_by_user_and_org(&conn, &path.user_id, &path.org_id)?
            .ok_or_else(|| AppError::NotFound("User is not a member of this org".into()))?;

    let limit = query.limit();
    let offset = query.offset();
    // Org owners can see all keys (not just user-manageable ones)
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
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<MemberApiKeyIdPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    // Only owner can revoke other members' keys, or member can revoke their own
    if path.user_id != ctx.member.user_id {
        ctx.require_owner()?;
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify the user is a member of this org
    let target_member =
        queries::get_org_member_with_user_by_user_and_org(&conn, &path.user_id, &path.org_id)?
            .ok_or_else(|| AppError::NotFound("User is not a member of this org".into()))?;

    // Verify key exists and belongs to the right user
    let key = queries::get_api_key_by_id(&conn, &path.key_id)?
        .ok_or_else(|| AppError::NotFound("API key not found".into()))?;

    if key.user_id != path.user_id {
        return Err(AppError::NotFound("API key not found".into()));
    }

    queries::revoke_api_key(&conn, &path.key_id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::RevokeApiKey)
        .resource("api_key", &path.key_id)
        .details(&serde_json::json!({
            "target_user_id": path.user_id,
            "target_email": target_member.email,
            "key_name": key.name,
            "impersonator": ctx.impersonator.as_ref().map(|i| serde_json::json!({
                "user_id": i.user_id,
                "email": i.email
            }))
        }))
        .org(&path.org_id)
        .names(&ctx.audit_names().resource(key.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}
