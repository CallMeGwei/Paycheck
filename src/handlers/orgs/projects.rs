use axum::{
    extract::{Extension, Path, State},
    http::HeaderMap,
    Json,
};

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::jwt;
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, CreateProject, ProjectPublic, UpdateProject};
use crate::util::extract_request_info;

pub async fn create_project(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<CreateProject>,
) -> Result<Json<ProjectPublic>> {
    ctx.require_admin()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Generate Ed25519 key pair
    let (private_key, public_key) = jwt::generate_keypair();

    let project = queries::create_project(&conn, &org_id, &input, &private_key, &public_key)?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "create_project",
        "project",
        &project.id,
        Some(&serde_json::json!({
            "name": input.name,
            "domain": input.domain,
        })),
        Some(&org_id),
        Some(&project.id),
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(project.into()))
}

pub async fn list_projects(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<ProjectPublic>>> {
    let conn = state.db.get()?;
    let projects = queries::list_projects_for_org(&conn, &org_id)?;

    // Filter based on access
    let accessible: Vec<ProjectPublic> = if ctx.member.role.has_implicit_project_access() {
        projects.into_iter().map(Into::into).collect()
    } else {
        // For 'member' role, only show projects they're explicitly added to
        projects
            .into_iter()
            .filter(|p| {
                queries::get_project_member(&conn, &ctx.member.id, &p.id)
                    .ok()
                    .flatten()
                    .is_some()
            })
            .map(Into::into)
            .collect()
    };

    Ok(Json(accessible))
}

pub async fn get_project(
    State(state): State<AppState>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
) -> Result<Json<ProjectPublic>> {
    let conn = state.db.get()?;
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    if project.org_id != path.org_id {
        return Err(AppError::NotFound("Project not found".into()));
    }

    Ok(Json(project.into()))
}

pub async fn update_project(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    headers: HeaderMap,
    Json(input): Json<UpdateProject>,
) -> Result<Json<ProjectPublic>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    queries::update_project(&conn, &path.project_id, &input)?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "update_project",
        "project",
        &path.project_id,
        Some(&serde_json::json!({
            "name": input.name,
            "domain": input.domain,
            "stripe_updated": input.stripe_config.is_some(),
            "ls_updated": input.ls_config.is_some(),
        })),
        Some(&path.org_id),
        Some(&path.project_id),
        ip.as_deref(),
        ua.as_deref(),
    )?;

    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    Ok(Json(project.into()))
}

pub async fn delete_project(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    ctx.require_admin()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    queries::delete_project(&conn, &path.project_id)?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "delete_project",
        "project",
        &path.project_id,
        Some(&serde_json::json!({
            "name": existing.name,
            "domain": existing.domain,
        })),
        Some(&path.org_id),
        Some(&path.project_id),
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
