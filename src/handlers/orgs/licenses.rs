use axum::{
    extract::{Extension, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, CreateLicenseKey, Device, LicenseKeyWithProduct};
use crate::util::{LicenseExpirations, audit_log};

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
    let licenses =
        queries::list_license_keys_for_project(&conn, &path.project_id, &state.master_key)?;
    Ok(Json(licenses))
}

/// Request body for creating a license directly (for bulk/trial licenses)
#[derive(Debug, Deserialize)]
pub struct CreateLicenseBody {
    /// Product ID to create the license for
    pub product_id: String,
    /// Developer-managed customer identifier (optional)
    /// Use this to link licenses to your own user/account system
    #[serde(default)]
    pub customer_id: Option<String>,
    /// Override license expiration (days from now, null for perpetual)
    /// If not specified, uses product's license_exp_days
    #[serde(default)]
    pub license_exp_days: Option<Option<i32>>,
    /// Override updates expiration (days from now)
    /// If not specified, uses product's updates_exp_days
    #[serde(default)]
    pub updates_exp_days: Option<Option<i32>>,
    /// Number of licenses to create (default: 1, max: 100)
    #[serde(default = "default_count")]
    pub count: i32,
}

fn default_count() -> i32 {
    1
}

#[derive(Debug, Serialize)]
pub struct CreateLicenseResponse {
    pub licenses: Vec<CreatedLicense>,
}

#[derive(Debug, Serialize)]
pub struct CreatedLicense {
    pub id: String,
    pub key: String,
    pub expires_at: Option<i64>,
    pub updates_expires_at: Option<i64>,
}

/// POST /orgs/{org_id}/projects/{project_id}/licenses
/// Create one or more licenses directly (for bulk/trial licenses)
/// Useful for gift cards, bulk purchases, or trial generation
pub async fn create_license(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    headers: HeaderMap,
    Json(body): Json<CreateLicenseBody>,
) -> Result<Json<CreateLicenseResponse>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    // Validate count
    if body.count < 1 || body.count > 100 {
        return Err(AppError::BadRequest(
            "Count must be between 1 and 100".into(),
        ));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify product exists and belongs to this project
    let product = queries::get_product_by_id(&conn, &body.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(
            "Product not found in this project".into(),
        ));
    }

    // Get project for license key prefix
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    // Compute expirations (use override if provided, otherwise use product defaults)
    let now = chrono::Utc::now().timestamp();
    let license_exp_days = body.license_exp_days.unwrap_or(product.license_exp_days);
    let updates_exp_days = body.updates_exp_days.unwrap_or(product.updates_exp_days);
    let exps = LicenseExpirations::from_days(license_exp_days, updates_exp_days, now);

    let mut created_licenses = Vec::with_capacity(body.count as usize);

    for _ in 0..body.count {
        let license = queries::create_license_key(
            &conn,
            &project.id,
            &body.product_id,
            &project.license_key_prefix,
            &CreateLicenseKey {
                customer_id: body.customer_id.clone(),
                expires_at: exps.license_exp,
                updates_expires_at: exps.updates_exp,
                payment_provider: None,
                payment_provider_customer_id: None,
                payment_provider_subscription_id: None,
                payment_provider_order_id: None,
            },
            &state.master_key,
        )?;

        created_licenses.push(CreatedLicense {
            id: license.id.clone(),
            key: license.key.clone(),
            expires_at: exps.license_exp,
            updates_expires_at: exps.updates_exp,
        });

        // Audit log for each license
        audit_log(
            &audit_conn,
            state.audit_log_enabled,
            ActorType::OrgMember,
            Some(&ctx.member.id),
            &headers,
            "create_license",
            "license_key",
            &license.id,
            Some(
                &serde_json::json!({ "key": license.key, "product_id": body.product_id, "expires_at": exps.license_exp }),
            ),
            Some(&path.org_id),
            Some(&path.project_id),
        )?;
    }

    tracing::info!(
        "Created {} license(s) for product {} (project: {})",
        created_licenses.len(),
        body.product_id,
        path.project_id
    );

    Ok(Json(CreateLicenseResponse {
        licenses: created_licenses,
    }))
}

pub async fn get_license(
    State(state): State<AppState>,
    Path(path): Path<LicensePath>,
) -> Result<Json<LicenseWithDevices>> {
    let conn = state.db.get()?;

    let license = queries::get_license_key_by_key(&conn, &path.key, &state.master_key)?
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

    let license = queries::get_license_key_by_key(&conn, &path.key, &state.master_key)?
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

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        &headers,
        "revoke_license",
        "license_key",
        &license.id,
        Some(&serde_json::json!({ "key": license.key })),
        Some(&path.org_id),
        Some(&path.project_id),
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
    let old_license = queries::get_license_key_by_key(&conn, &path.key, &state.master_key)?
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

    // Create a new license with the same settings (preserving customer_id and payment info)
    // Note: subscription_id is NOT copied - the old subscription is tied to the old key
    // If this is a subscription, the customer will need to update their payment method
    let new_license = queries::create_license_key(
        &conn,
        &project.id,
        &old_license.product_id,
        &project.license_key_prefix,
        &CreateLicenseKey {
            customer_id: old_license.customer_id.clone(),
            expires_at: old_license.expires_at,
            updates_expires_at: old_license.updates_expires_at,
            payment_provider: old_license.payment_provider.clone(),
            payment_provider_customer_id: old_license.payment_provider_customer_id.clone(),
            payment_provider_subscription_id: old_license.payment_provider_subscription_id.clone(),
            payment_provider_order_id: old_license.payment_provider_order_id.clone(),
        },
        &state.master_key,
    )?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        &headers,
        "replace_license",
        "license_key",
        &new_license.id,
        Some(
            &serde_json::json!({ "old_key": old_license.key, "old_license_id": old_license.id, "new_key": new_license.key, "reason": "key_replacement" }),
        ),
        Some(&path.org_id),
        Some(&path.project_id),
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
    let license = queries::get_license_key_by_key(&conn, &path.key, &state.master_key)?
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
    queries::add_revoked_jti(&conn, &license.id, &device.jti, &state.master_key)?;

    // Delete the device record
    queries::delete_device(&conn, &device.id)?;

    // Get remaining device count
    let remaining = queries::count_devices_for_license(&conn, &license.id)?;

    // Audit log
    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        &headers,
        "deactivate_device",
        "device",
        &device.id,
        Some(
            &serde_json::json!({ "license_key": license.key, "device_id": path.device_id, "device_name": device.name, "reason": "admin_remote_deactivation" }),
        ),
        Some(&path.org_id),
        Some(&path.project_id),
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
