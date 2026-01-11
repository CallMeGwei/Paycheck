use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, AuditAction, CreateOrgMember, OrgMember, OrgMemberWithUser, UpdateOrgMember};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::AuditLogBuilder;

/// Create an org member (link a user to an org with a role).
/// The user must already exist in the users table.
/// No API key is created - use Console or create one separately.
pub async fn create_org_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<CreateOrgMember>,
) -> Result<Json<OrgMember>> {
    ctx.require_owner()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify the user exists
    let user = queries::get_user_by_id(&conn, &input.user_id)?
        .ok_or_else(|| AppError::BadRequest("User not found".into()))?;

    let member = queries::create_org_member(&conn, &org_id, &input)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::CreateOrgMember)
        .resource("org_member", &member.id)
        .details(&serde_json::json!({
            "user_id": input.user_id,
            "email": user.email,
            "role": input.role,
            "impersonator": ctx.impersonator.as_ref().map(|i| serde_json::json!({
                "user_id": i.user_id,
                "email": i.email
            }))
        }))
        .org(&org_id)
        .names(&ctx.audit_names().resource(user.name.clone()))
        .save()?;

    Ok(Json(member))
}

/// List org members with user details
pub async fn list_org_members(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Paginated<OrgMemberWithUser>>> {
    let conn = state.db.get()?;
    let limit = pagination.limit();
    let offset = pagination.offset();
    let (members, total) =
        queries::list_org_members_with_user_paginated(&conn, &org_id, limit, offset)?;
    Ok(Json(Paginated::new(members, total, limit, offset)))
}

#[derive(serde::Deserialize)]
pub struct OrgMemberPath {
    pub org_id: String,
    pub member_id: String,
}

/// Get an org member with user details
pub async fn get_org_member(
    State(state): State<AppState>,
    Path(path): Path<OrgMemberPath>,
) -> Result<Json<OrgMemberWithUser>> {
    let conn = state.db.get()?;
    let member = queries::get_org_member_with_user_by_id(&conn, &path.member_id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    if member.org_id != path.org_id {
        return Err(AppError::NotFound("Member not found".into()));
    }

    Ok(Json(member))
}

pub async fn update_org_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<OrgMemberPath>,
    headers: HeaderMap,
    Json(input): Json<UpdateOrgMember>,
) -> Result<Json<OrgMemberWithUser>> {
    ctx.require_owner()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_org_member_with_user_by_id(&conn, &path.member_id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    if existing.org_id != path.org_id {
        return Err(AppError::NotFound("Member not found".into()));
    }

    // Prevent changing your own role
    if path.member_id == ctx.member.id && input.role.is_some() {
        return Err(AppError::BadRequest("Cannot change your own role".into()));
    }

    queries::update_org_member(&conn, &path.member_id, &input)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::UpdateOrgMember)
        .resource("org_member", &path.member_id)
        .details(&serde_json::json!({
            "role": input.role,
            "impersonator": ctx.impersonator.as_ref().map(|i| serde_json::json!({
                "user_id": i.user_id,
                "email": i.email
            }))
        }))
        .org(&path.org_id)
        .names(&ctx.audit_names().resource(existing.name.clone()))
        .save()?;

    let member = queries::get_org_member_with_user_by_id(&conn, &path.member_id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    Ok(Json(member))
}

pub async fn delete_org_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<OrgMemberPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    ctx.require_owner()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Prevent self-deletion
    if path.member_id == ctx.member.id {
        return Err(AppError::BadRequest("Cannot delete yourself".into()));
    }

    let existing = queries::get_org_member_with_user_by_id(&conn, &path.member_id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    if existing.org_id != path.org_id {
        return Err(AppError::NotFound("Member not found".into()));
    }

    queries::delete_org_member(&conn, &path.member_id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::DeleteOrgMember)
        .resource("org_member", &path.member_id)
        .details(&serde_json::json!({
            "user_id": existing.user_id,
            "email": existing.email,
            "impersonator": ctx.impersonator.as_ref().map(|i| serde_json::json!({
                "user_id": i.user_id,
                "email": i.email
            }))
        }))
        .org(&path.org_id)
        .names(&ctx.audit_names().resource(existing.name.clone()))
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}
