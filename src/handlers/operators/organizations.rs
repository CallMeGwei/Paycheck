use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OperatorContext;
use crate::models::{
    ActorType, AuditAction, CreateOrgMember, CreateOrganization, OrgMember, OrgMemberRole, Organization,
    UpdateOrganization,
};
use crate::pagination::Paginated;
use crate::util::AuditLogBuilder;

#[derive(Serialize)]
pub struct OrganizationCreated {
    pub organization: Organization,
    /// Owner member (if owner_user_id provided). No API key - use Console or create one later.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<OrgMember>,
}

pub async fn create_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Json(input): Json<CreateOrganization>,
) -> Result<Json<OrganizationCreated>> {
    input.validate()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;
    let organization = queries::create_organization(&conn, &input)?;

    // If owner_user_id is provided, create the first org member as owner
    // The user must already exist in the users table
    // No API key is created - owner uses Console (impersonation) or creates a key later
    let owner = if let Some(owner_user_id) = &input.owner_user_id {
        // Verify the user exists
        let user = queries::get_user_by_id(&conn, owner_user_id)?
            .ok_or_else(|| AppError::BadRequest("Owner user not found".into()))?;

        let member = queries::create_org_member(
            &conn,
            &organization.id,
            &CreateOrgMember {
                user_id: owner_user_id.clone(),
                role: OrgMemberRole::Owner,
            },
        )?;

        // Log details with user info
        AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
            .actor(ActorType::User, Some(&ctx.user.id))
            .action(AuditAction::CreateOrganization)
            .resource("organization", &organization.id)
            .details(&serde_json::json!({
                "name": input.name,
                "owner_user_id": owner_user_id,
                "owner_email": user.email
            }))
            .names(&ctx.audit_names().resource(organization.name.clone()))
            .save()?;

        Some(member)
    } else {
        AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
            .actor(ActorType::User, Some(&ctx.user.id))
            .action(AuditAction::CreateOrganization)
            .resource("organization", &organization.id)
            .details(&serde_json::json!({
                "name": input.name
            }))
            .names(&ctx.audit_names().resource(organization.name.clone()))
            .save()?;

        None
    };

    Ok(Json(OrganizationCreated { organization, owner }))
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
) -> Result<Json<Paginated<Organization>>> {
    let conn = state.db.get()?;
    let limit = query.limit();
    let offset = query.offset();

    let (organizations, total) = if let Some(user_id) = &query.user_id {
        // Filter by user ID - returns orgs where user is a member
        queries::list_orgs_by_user_id_paginated(&conn, user_id, limit, offset)?
    } else {
        queries::list_organizations_paginated(&conn, limit, offset)?
    };

    Ok(Json(Paginated::new(organizations, total, limit, offset)))
}

pub async fn get_organization(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Organization>> {
    let conn = state.db.get()?;
    let organization = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;
    Ok(Json(organization))
}

pub async fn update_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateOrganization>,
) -> Result<Json<Organization>> {
    input.validate()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify organization exists
    let existing = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    queries::update_organization(&conn, &id, &input, &state.master_key)?;

    // Fetch updated organization
    let organization = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::Internal("Organization not found after update".into()))?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::UpdateOrganization)
        .resource("organization", &id)
        .details(&serde_json::json!({ "old_name": existing.name, "new_name": input.name, "stripe_updated": input.stripe_config.is_some(), "ls_updated": input.ls_config.is_some() }))
        .names(&ctx.audit_names().resource(organization.name.clone()))
        .save()?;

    Ok(Json(organization))
}

pub async fn delete_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    queries::delete_organization(&conn, &id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::DeleteOrganization)
        .resource("organization", &id)
        .details(&serde_json::json!({ "name": existing.name }))
        .names(&ctx.audit_names().resource(existing.name.clone()))
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}
