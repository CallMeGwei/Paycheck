use axum::{
    extract::{Extension, Path, State},
    http::HeaderMap,
    Json,
};
use serde::Serialize;

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, CreateOrgMember, OrgMember, UpdateOrgMember};
use crate::util::extract_request_info;

#[derive(Serialize)]
pub struct OrgMemberCreated {
    pub member: OrgMember,
    pub api_key: String,
}

pub async fn create_org_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<CreateOrgMember>,
) -> Result<Json<OrgMemberCreated>> {
    ctx.require_owner()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;
    let api_key = queries::generate_api_key();
    let member = queries::create_org_member(&conn, &org_id, &input, &api_key)?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "create_org_member",
        "org_member",
        &member.id,
        Some(&serde_json::json!({
            "email": input.email,
            "role": input.role,
        })),
        Some(&org_id),
        None,
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(OrgMemberCreated { member, api_key }))
}

pub async fn list_org_members(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<OrgMember>>> {
    let conn = state.db.get()?;
    let members = queries::list_org_members(&conn, &org_id)?;
    Ok(Json(members))
}

#[derive(serde::Deserialize)]
pub struct OrgMemberPath {
    pub org_id: String,
    pub id: String,
}

pub async fn get_org_member(
    State(state): State<AppState>,
    Path(path): Path<OrgMemberPath>,
) -> Result<Json<OrgMember>> {
    let conn = state.db.get()?;
    let member = queries::get_org_member_by_id(&conn, &path.id)?
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
) -> Result<Json<OrgMember>> {
    ctx.require_owner()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_org_member_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    if existing.org_id != path.org_id {
        return Err(AppError::NotFound("Member not found".into()));
    }

    // Prevent changing your own role
    if path.id == ctx.member.id && input.role.is_some() {
        return Err(AppError::BadRequest("Cannot change your own role".into()));
    }

    queries::update_org_member(&conn, &path.id, &input)?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "update_org_member",
        "org_member",
        &path.id,
        Some(&serde_json::json!({
            "name": input.name,
            "role": input.role,
        })),
        Some(&path.org_id),
        None,
        ip.as_deref(),
        ua.as_deref(),
    )?;

    let member = queries::get_org_member_by_id(&conn, &path.id)?
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
    if path.id == ctx.member.id {
        return Err(AppError::BadRequest("Cannot delete yourself".into()));
    }

    let existing = queries::get_org_member_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    if existing.org_id != path.org_id {
        return Err(AppError::NotFound("Member not found".into()));
    }

    queries::delete_org_member(&conn, &path.id)?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "delete_org_member",
        "org_member",
        &path.id,
        Some(&serde_json::json!({
            "email": existing.email,
        })),
        Some(&path.org_id),
        None,
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
