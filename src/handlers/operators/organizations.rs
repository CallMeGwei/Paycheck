use axum::{
    extract::{Extension, State},
    http::HeaderMap,
};
use serde::Serialize;

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OperatorContext;
use crate::models::{ActorType, CreateOrganization, OrgMemberRole, Organization, CreateOrgMember, UpdateOrganization};
use crate::util::extract_request_info;

#[derive(Serialize)]
pub struct OrganizationCreated {
    pub organization: Organization,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_api_key: Option<String>,
}

pub async fn create_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Json(input): Json<CreateOrganization>,
) -> Result<Json<OrganizationCreated>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;
    let organization = queries::create_organization(&conn, &input)?;

    // If owner email is provided, create the first org member as owner
    let owner_api_key = if let (Some(email), Some(name)) = (&input.owner_email, &input.owner_name) {
        let api_key = queries::generate_api_key();
        queries::create_org_member(
            &conn,
            &organization.id,
            &CreateOrgMember {
                email: email.clone(),
                name: name.clone(),
                role: OrgMemberRole::Owner,
            },
            &api_key,
        )?;
        Some(api_key)
    } else {
        None
    };

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::Operator,
        Some(&ctx.operator.id),
        "create_organization",
        "organization",
        &organization.id,
        Some(&serde_json::json!({
            "name": input.name,
            "owner_email": input.owner_email,
        })),
        Some(&organization.id),
        None,
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(OrganizationCreated {
        organization,
        owner_api_key,
    }))
}

pub async fn list_organizations(State(state): State<AppState>) -> Result<Json<Vec<Organization>>> {
    let conn = state.db.get()?;
    let organizations = queries::list_organizations(&conn)?;
    Ok(Json(organizations))
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
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify organization exists
    let existing = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    queries::update_organization(&conn, &id, &input, &state.master_key)?;

    // Fetch updated organization
    let organization = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::Internal("Organization not found after update".into()))?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::Operator,
        Some(&ctx.operator.id),
        "update_organization",
        "organization",
        &id,
        Some(&serde_json::json!({
            "old_name": existing.name,
            "new_name": input.name,
            "stripe_updated": input.stripe_config.is_some(),
            "ls_updated": input.ls_config.is_some(),
        })),
        Some(&id),
        None,
        ip.as_deref(),
        ua.as_deref(),
    )?;

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

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::Operator,
        Some(&ctx.operator.id),
        "delete_organization",
        "organization",
        &id,
        Some(&serde_json::json!({
            "name": existing.name,
        })),
        Some(&id),
        None,
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
