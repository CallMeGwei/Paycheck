use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::Deserialize;

use crate::db::{AppState, queries};
use crate::error::{AppError, OptionExt, Result, msg};
use crate::extractors::{Json, Path};
use crate::middleware::OperatorContext;
use crate::models::{
    ActorType, AuditAction, CreateOrgMember, CreateOrganization, OrgMemberRole,
    OrganizationPublic, UpdateOrganization,
};
use crate::pagination::Paginated;
use crate::util::AuditLogBuilder;

pub async fn create_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Json(input): Json<CreateOrganization>,
) -> Result<Json<OrganizationPublic>> {
    input.validate()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;
    let organization = queries::create_organization(&conn, &input)?;

    // If owner_user_id is provided, create the first org member as owner
    // The user must already exist in the users table
    // No API key is created - owner uses Console (impersonation) or creates a key later
    let audit_details = if let Some(owner_user_id) = &input.owner_user_id {
        let user = queries::get_user_by_id(&conn, owner_user_id)?
            .ok_or_else(|| AppError::BadRequest(msg::OWNER_USER_NOT_FOUND.into()))?;

        queries::create_org_member(
            &conn,
            &organization.id,
            &CreateOrgMember {
                user_id: owner_user_id.clone(),
                role: OrgMemberRole::Owner,
            },
        )?;

        serde_json::json!({
            "name": input.name,
            "owner_user_id": owner_user_id,
            "owner_email": user.email
        })
    } else {
        serde_json::json!({ "name": input.name })
    };

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::CreateOrg)
        .resource("org", &organization.id)
        .details(&audit_details)
        .names(&ctx.audit_names().resource(organization.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(organization.into()))
}

/// Query parameters for listing organizations
#[derive(Deserialize)]
pub struct ListOrgsQuery {
    /// Filter by user ID (returns orgs where user is a member)
    pub user_id: Option<String>,
    /// Pagination: max items to return (default: 50, max: 100)
    pub limit: Option<i64>,
    /// Pagination: items to skip (default: 0)
    pub offset: Option<i64>,
    /// Include soft-deleted organizations (default: false)
    #[serde(default)]
    pub include_deleted: bool,
}

impl ListOrgsQuery {
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(50).clamp(1, 100)
    }

    fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }
}

pub async fn list_organizations(
    State(state): State<AppState>,
    Query(query): Query<ListOrgsQuery>,
) -> Result<Json<Paginated<OrganizationPublic>>> {
    let conn = state.db.get()?;
    let limit = query.limit();
    let offset = query.offset();

    let (organizations, total) = if let Some(user_id) = &query.user_id {
        // Filter by user ID - returns orgs where user is a member
        // Note: include_deleted is not supported for this filter
        queries::list_orgs_by_user_id_paginated(&conn, user_id, limit, offset)?
    } else {
        queries::list_organizations_paginated(&conn, limit, offset, query.include_deleted)?
    };

    let organizations_public: Vec<OrganizationPublic> =
        organizations.into_iter().map(Into::into).collect();

    Ok(Json(Paginated::new(
        organizations_public,
        total,
        limit,
        offset,
    )))
}

pub async fn get_organization(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<OrganizationPublic>> {
    let conn = state.db.get()?;
    let organization =
        queries::get_organization_by_id(&conn, &id)?.or_not_found(msg::ORG_NOT_FOUND)?;
    Ok(Json(organization.into()))
}

pub async fn update_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateOrganization>,
) -> Result<Json<OrganizationPublic>> {
    input.validate()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify organization exists
    let existing = queries::get_organization_by_id(&conn, &id)?.or_not_found(msg::ORG_NOT_FOUND)?;

    queries::update_organization(&conn, &id, &input, &state.master_key)?;

    // Fetch updated organization
    let organization = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::Internal(msg::ORG_NOT_FOUND_AFTER_UPDATE.into()))?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::UpdateOrg)
        .resource("org", &id)
        .details(&serde_json::json!({ "old_name": existing.name, "new_name": input.name, "stripe_updated": input.stripe_config.is_some(), "ls_updated": input.ls_config.is_some() }))
        .names(&ctx.audit_names().resource(organization.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(organization.into()))
}

pub async fn delete_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_organization_by_id(&conn, &id)?.or_not_found(msg::ORG_NOT_FOUND)?;

    queries::soft_delete_organization(&conn, &id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::DeleteOrg)
        .resource("org", &id)
        .details(&serde_json::json!({ "name": existing.name }))
        .names(&ctx.audit_names().resource(existing.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}

/// Restore a soft-deleted organization and its cascade-deleted children
pub async fn restore_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<OrganizationPublic>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Get the deleted organization (need to check it exists and was deleted)
    let existing = queries::get_deleted_organization_by_id(&conn, &id)?
        .or_not_found(msg::DELETED_ORG_NOT_FOUND)?;

    // Restore the organization and cascade-deleted children
    queries::restore_organization(&conn, &id)?;

    // Get the restored organization
    let organization = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::Internal(msg::ORG_NOT_FOUND_AFTER_RESTORE.into()))?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::RestoreOrg)
        .resource("org", &id)
        .details(&serde_json::json!({ "name": existing.name }))
        .names(&ctx.audit_names().resource(organization.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(organization.into()))
}

/// Hard delete an organization (GDPR compliance - permanently removes all data).
/// This is irreversible and removes all associated data including:
/// - All org members
/// - All projects and their products
/// - All licenses
pub async fn hard_delete_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Get org info for audit log (may be soft-deleted already)
    let existing = queries::get_organization_by_id(&conn, &id)?
        .or_else(|| {
            queries::get_deleted_organization_by_id(&conn, &id)
                .ok()
                .flatten()
        })
        .or_not_found(msg::ORG_NOT_FOUND)?;

    // Perform hard delete (CASCADE removes all related data)
    queries::delete_organization(&conn, &id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::HardDeleteOrg)
        .resource("org", &id)
        .details(&serde_json::json!({
            "name": existing.name,
            "reason": "gdpr_request"
        }))
        .names(&ctx.audit_names().resource(existing.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    tracing::warn!(
        "GDPR hard delete: Organization {} ({}) permanently deleted by operator {}",
        id,
        existing.name,
        ctx.user.id
    );

    Ok(Json(
        serde_json::json!({ "success": true, "permanently_deleted": true }),
    ))
}
