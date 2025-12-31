use axum::{
    extract::{Extension, Path, State},
    http::HeaderMap,
    Json,
};
use serde::Serialize;

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, CreateLicenseKey, Device, LicenseKeyWithProduct};

fn extract_request_info(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    (ip, user_agent)
}

#[derive(serde::Deserialize)]
pub struct LicensePath {
    pub org_id: String,
    pub project_id: String,
    pub key: String,
}

#[derive(serde::Deserialize)]
pub struct LicenseDevicePath {
    pub org_id: String,
    pub project_id: String,
    pub key: String,
    pub device_id: String,
}

#[derive(Serialize)]
pub struct LicenseWithDevices {
    #[serde(flatten)]
    pub license: LicenseKeyWithProduct,
    pub devices: Vec<Device>,
}

pub async fn list_licenses(
    State(state): State<AppState>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
) -> Result<Json<Vec<LicenseKeyWithProduct>>> {
    let conn = state.db.get()?;
    let licenses = queries::list_license_keys_for_project(&conn, &path.project_id)?;
    Ok(Json(licenses))
}

pub async fn get_license(
    State(state): State<AppState>,
    Path(path): Path<LicensePath>,
) -> Result<Json<LicenseWithDevices>> {
    let conn = state.db.get()?;

    let license = queries::get_license_key_by_key(&conn, &path.key)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("License not found".into()));
    }

    let devices = queries::list_devices_for_license(&conn, &license.id)?;

    Ok(Json(LicenseWithDevices {
        license: LicenseKeyWithProduct {
            license,
            product_name: product.name,
            project_id: product.project_id,
        },
        devices,
    }))
}

pub async fn revoke_license(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<LicensePath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let license = queries::get_license_key_by_key(&conn, &path.key)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("License not found".into()));
    }

    if license.revoked {
        return Err(AppError::BadRequest("License is already revoked".into()));
    }

    queries::revoke_license_key(&conn, &license.id)?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "revoke_license",
        "license_key",
        &license.id,
        Some(&serde_json::json!({
            "key": license.key,
            "email": license.email,
        })),
        Some(&path.org_id),
        Some(&path.project_id),
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(serde_json::json!({ "revoked": true })))
}

#[derive(Serialize)]
pub struct ReplaceLicenseResponse {
    pub old_key: String,
    pub new_key: String,
    pub new_license_id: String,
}

pub async fn replace_license(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<LicensePath>,
    headers: HeaderMap,
) -> Result<Json<ReplaceLicenseResponse>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Get the old license
    let old_license = queries::get_license_key_by_key(&conn, &path.key)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &old_license.product_id)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("License not found".into()));
    }

    // Get the project for license key prefix
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    // Revoke the old license
    if !old_license.revoked {
        queries::revoke_license_key(&conn, &old_license.id)?;
    }

    // Create a new license with the same settings (preserving payment info)
    // Note: subscription_id is NOT copied - the old subscription is tied to the old key
    // If this is a subscription, the customer will need to update their payment method
    let new_license = queries::create_license_key(
        &conn,
        &old_license.product_id,
        &project.license_key_prefix,
        &CreateLicenseKey {
            email: old_license.email.clone(),
            expires_at: old_license.expires_at,
            updates_expires_at: old_license.updates_expires_at,
            payment_provider: old_license.payment_provider.clone(),
            payment_provider_customer_id: old_license.payment_provider_customer_id.clone(),
            payment_provider_subscription_id: old_license.payment_provider_subscription_id.clone(),
        },
    )?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "replace_license",
        "license_key",
        &new_license.id,
        Some(&serde_json::json!({
            "old_key": old_license.key,
            "old_license_id": old_license.id,
            "new_key": new_license.key,
            "email": old_license.email,
            "reason": "key_replacement",
        })),
        Some(&path.org_id),
        Some(&path.project_id),
        ip.as_deref(),
        ua.as_deref(),
    )?;

    tracing::info!(
        "License replaced: {} -> {} (project: {})",
        old_license.key,
        new_license.key,
        path.project_id
    );

    Ok(Json(ReplaceLicenseResponse {
        old_key: old_license.key,
        new_key: new_license.key,
        new_license_id: new_license.id,
    }))
}

#[derive(Serialize)]
pub struct DeactivateDeviceResponse {
    pub deactivated: bool,
    pub device_id: String,
    pub remaining_devices: i32,
}

/// Remote device deactivation for org admins
/// Used for lost device recovery when user contacts support
pub async fn deactivate_device_admin(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<LicenseDevicePath>,
    headers: HeaderMap,
) -> Result<Json<DeactivateDeviceResponse>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Get the license
    let license = queries::get_license_key_by_key(&conn, &path.key)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("License not found".into()));
    }

    // Find the device
    let device = queries::get_device_for_license(&conn, &license.id, &path.device_id)?
        .ok_or_else(|| AppError::NotFound("Device not found".into()))?;

    // Add the device's JTI to revoked list so the token can't be used anymore
    queries::add_revoked_jti(&conn, &license.id, &device.jti)?;

    // Delete the device record
    queries::delete_device(&conn, &device.id)?;

    // Get remaining device count
    let remaining = queries::count_devices_for_license(&conn, &license.id)?;

    // Audit log
    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "deactivate_device",
        "device",
        &device.id,
        Some(&serde_json::json!({
            "license_key": license.key,
            "device_id": path.device_id,
            "device_name": device.name,
            "reason": "admin_remote_deactivation",
        })),
        Some(&path.org_id),
        Some(&path.project_id),
        ip.as_deref(),
        ua.as_deref(),
    )?;

    tracing::info!(
        "Device deactivated by admin: {} on license {} (project: {})",
        path.device_id,
        license.key,
        path.project_id
    );

    Ok(Json(DeactivateDeviceResponse {
        deactivated: true,
        device_id: path.device_id,
        remaining_devices: remaining,
    }))
}
