use axum::{
    extract::{Extension, State},
    http::HeaderMap,
};

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::jwt;
use crate::middleware::OrgMemberContext;
use crate::models::{
    ActorType, CreateProject, LemonSqueezyConfigMasked, ProjectPublic, StripeConfigMasked,
    UpdateProject,
};
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

    // Generate a temporary project ID for encryption (will be used as the actual ID)
    let project_id = uuid::Uuid::new_v4().to_string();

    // Encrypt the private key with envelope encryption
    let encrypted_private_key = state
        .master_key
        .encrypt_private_key(&project_id, &private_key)?;

    let project = queries::create_project_with_id(
        &conn,
        &project_id,
        &org_id,
        &input,
        &encrypted_private_key,
        &public_key,
    )?;

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

#[derive(Debug, serde::Serialize)]
pub struct PaymentConfigResponse {
    pub org_id: String,
    pub stripe_config: Option<StripeConfigMasked>,
    pub ls_config: Option<LemonSqueezyConfigMasked>,
    pub default_provider: Option<String>,
}

/// Get payment provider configuration for the organization (masked for security)
pub async fn get_payment_config(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(org_id): Path<String>,
) -> Result<Json<PaymentConfigResponse>> {
    // Only admins can view payment config
    ctx.require_admin()?;

    let conn = state.db.get()?;
    let org = queries::get_organization_by_id(&conn, &org_id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    let stripe_config = org
        .decrypt_stripe_config(&state.master_key)?
        .as_ref()
        .map(StripeConfigMasked::from);

    let ls_config = org
        .decrypt_ls_config(&state.master_key)?
        .as_ref()
        .map(LemonSqueezyConfigMasked::from);

    Ok(Json(PaymentConfigResponse {
        org_id,
        stripe_config,
        ls_config,
        default_provider: org.default_provider,
    }))
}
