use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use rusqlite::Connection;
use serde::Deserialize;

use crate::db::{AppState, queries};
use crate::error::{AppError, OptionExt, Result, msg};
use crate::extractors::{Json, Path};
use crate::middleware::OperatorContext;
use crate::models::{
    ActorType, AuditAction, CreateOrgMember, CreateOrganization, OrgMemberRole, Organization,
    OrganizationPublic, ServiceProvider, UpdateOrganization,
};
use crate::pagination::Paginated;
use crate::util::AuditLogBuilder;
use std::collections::HashMap;

/// Helper to convert Organization to OrganizationPublic by querying service configs
fn org_to_public(conn: &Connection, org: Organization) -> Result<OrganizationPublic> {
    let configs = queries::get_org_service_configs(conn, &org.id)?;

    // Group providers by category
    let mut configured_services: HashMap<String, Vec<String>> = HashMap::new();
    for config in configs {
        configured_services
            .entry(config.category.as_str().to_string())
            .or_default()
            .push(config.provider.as_str().to_string());
    }

    Ok(OrganizationPublic::from_with_configs(org, configured_services))
}

/// Helper to convert multiple Organizations to OrganizationPublic
fn orgs_to_public(conn: &Connection, orgs: Vec<Organization>) -> Result<Vec<OrganizationPublic>> {
    orgs.into_iter().map(|org| org_to_public(conn, org)).collect()
}

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

    Ok(Json(org_to_public(&conn, organization)?))
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

    let organizations_public = orgs_to_public(&conn, organizations)?;

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
    Ok(Json(org_to_public(&conn, organization)?))
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

    // Track what configs are being updated for audit
    let mut stripe_updated = false;
    let mut ls_updated = false;
    let mut resend_updated = false;

    // Handle Stripe config: Some(Some(config)) = set, Some(None) = clear, None = unchanged
    if let Some(ref stripe_config_opt) = input.stripe_config {
        match stripe_config_opt {
            Some(config) => {
                let json = serde_json::to_string(config)?;
                let encrypted = state.master_key.encrypt_private_key(&id, json.as_bytes())?;
                queries::upsert_org_service_config(&conn, &id, ServiceProvider::Stripe, &encrypted)?;
                stripe_updated = true;
            }
            None => {
                // Clear the config - also clear payment_provider if it was stripe
                if queries::delete_org_service_config(&conn, &id, ServiceProvider::Stripe)? {
                    stripe_updated = true;
                    if existing.payment_provider.as_deref() == Some("stripe") {
                        queries::clear_org_payment_provider(&conn, &id)?;
                    }
                }
            }
        }
    }

    // Handle LemonSqueezy config
    if let Some(ref ls_config_opt) = input.ls_config {
        match ls_config_opt {
            Some(config) => {
                let json = serde_json::to_string(config)?;
                let encrypted = state.master_key.encrypt_private_key(&id, json.as_bytes())?;
                queries::upsert_org_service_config(&conn, &id, ServiceProvider::LemonSqueezy, &encrypted)?;
                ls_updated = true;
            }
            None => {
                // Clear the config - also clear payment_provider if it was lemonsqueezy
                if queries::delete_org_service_config(&conn, &id, ServiceProvider::LemonSqueezy)? {
                    ls_updated = true;
                    if existing.payment_provider.as_deref() == Some("lemonsqueezy") {
                        queries::clear_org_payment_provider(&conn, &id)?;
                    }
                }
            }
        }
    }

    // Handle Resend API key
    if let Some(ref resend_opt) = input.resend_api_key {
        match resend_opt {
            Some(api_key) => {
                let encrypted = state.master_key.encrypt_private_key(&id, api_key.as_bytes())?;
                queries::upsert_org_service_config(&conn, &id, ServiceProvider::Resend, &encrypted)?;
                resend_updated = true;
            }
            None => {
                if queries::delete_org_service_config(&conn, &id, ServiceProvider::Resend)? {
                    resend_updated = true;
                }
            }
        }
    }

    // Validate payment_provider before setting
    if let Some(Some(ref provider)) = input.payment_provider {
        let provider_enum = match provider.as_str() {
            "stripe" => ServiceProvider::Stripe,
            "lemonsqueezy" => ServiceProvider::LemonSqueezy,
            _ => return Err(AppError::BadRequest(msg::INVALID_PROVIDER.into())),
        };

        // Check if config exists (either already in DB or being set in this request)
        let has_config = match provider_enum {
            ServiceProvider::Stripe => {
                input.stripe_config.as_ref().map(|o| o.is_some()).unwrap_or(false)
                    || queries::org_has_service_config(&conn, &id, ServiceProvider::Stripe)?
            }
            ServiceProvider::LemonSqueezy => {
                input.ls_config.as_ref().map(|o| o.is_some()).unwrap_or(false)
                    || queries::org_has_service_config(&conn, &id, ServiceProvider::LemonSqueezy)?
            }
            _ => false,
        };

        if !has_config {
            return Err(AppError::BadRequest(format!(
                "Cannot set payment_provider to '{}': no {} configuration exists. Configure {} first.",
                provider, provider, provider
            )));
        }
    }

    // Update basic org fields (name, payment_provider)
    queries::update_organization(&conn, &id, &input)?;

    // Fetch updated organization
    let organization = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::Internal(msg::ORG_NOT_FOUND_AFTER_UPDATE.into()))?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::UpdateOrg)
        .resource("org", &id)
        .details(&serde_json::json!({
            "old_name": existing.name,
            "new_name": input.name,
            "stripe_updated": stripe_updated,
            "ls_updated": ls_updated,
            "resend_updated": resend_updated
        }))
        .names(&ctx.audit_names().resource(organization.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(org_to_public(&conn, organization)?))
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

    Ok(Json(org_to_public(&conn, organization)?))
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
