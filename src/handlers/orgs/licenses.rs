use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, CreateLicense, Device, LicenseWithProduct};
use crate::util::{LicenseExpirations, audit_log};

#[derive(serde::Deserialize)]
pub struct LicensePath {
    pub org_id: String,
    pub project_id: String,
    pub license_id: String,
}

#[derive(serde::Deserialize)]
pub struct LicenseDevicePath {
    pub org_id: String,
    pub project_id: String,
    pub license_id: String,
    pub device_id: String,
}

#[derive(Serialize)]
pub struct LicenseWithDevices {
    #[serde(flatten)]
    pub license: LicenseWithProduct,
    pub devices: Vec<Device>,
}

#[derive(Debug, Deserialize)]
pub struct ListLicensesQuery {
    /// Filter licenses by customer email (for support lookups)
    pub email: Option<String>,
    /// Max results to return (default 50, max 100)
    pub limit: Option<i64>,
    /// Offset for pagination (default 0)
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListLicensesResponse {
    pub licenses: Vec<LicenseWithProduct>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// GET /orgs/{org_id}/projects/{project_id}/licenses
/// List licenses for a project with pagination, optionally filtered by email.
/// When filtering by email, returns ALL licenses including expired/revoked (for support).
pub async fn list_licenses(
    State(state): State<AppState>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    Query(query): Query<ListLicensesQuery>,
) -> Result<Json<ListLicensesResponse>> {
    let conn = state.db.get()?;

    let limit = query.limit.unwrap_or(50).min(100).max(1);
    let offset = query.offset.unwrap_or(0).max(0);

    let (licenses, total) = if let Some(email) = query.email {
        // Support lookup by email - includes expired/revoked
        let email_hash = queries::hash_email(&email);
        queries::get_all_licenses_by_email_hash_for_admin_paginated(
            &conn,
            &path.project_id,
            &email_hash,
            limit,
            offset,
        )?
    } else {
        // Default: list all licenses for project
        queries::list_licenses_for_project_paginated(&conn, &path.project_id, limit, offset)?
    };

    Ok(Json(ListLicensesResponse {
        licenses,
        total,
        limit,
        offset,
    }))
}

/// Request body for creating a license directly (for bulk/trial licenses)
#[derive(Debug, Deserialize)]
pub struct CreateLicenseBody {
    /// Product ID to create the license for
    pub product_id: String,
    /// Email address for the license (optional - enables license recovery via email)
    #[serde(default)]
    pub email: Option<String>,
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
    /// Activation code for immediate use (only included when count=1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_code_expires_at: Option<i64>,
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

    // Get project for activation code prefix
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    // Compute email hash if email provided
    let email_hash = body.email.as_ref().map(|e| queries::hash_email(e));

    // Compute expirations (use override if provided, otherwise use product defaults)
    let now = chrono::Utc::now().timestamp();
    let license_exp_days = body.license_exp_days.unwrap_or(product.license_exp_days);
    let updates_exp_days = body.updates_exp_days.unwrap_or(product.updates_exp_days);
    let exps = LicenseExpirations::from_days(license_exp_days, updates_exp_days, now);

    let mut created_licenses = Vec::with_capacity(body.count as usize);

    for _ in 0..body.count {
        let license = queries::create_license(
            &conn,
            &project.id,
            &body.product_id,
            &CreateLicense {
                email_hash: email_hash.clone(),
                customer_id: body.customer_id.clone(),
                expires_at: exps.license_exp,
                updates_expires_at: exps.updates_exp,
                payment_provider: None,
                payment_provider_customer_id: None,
                payment_provider_subscription_id: None,
                payment_provider_order_id: None,
            },
        )?;

        // Generate activation code for single license creation (useful for immediate distribution)
        let (activation_code, activation_code_expires_at) = if body.count == 1 {
            let code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)?;
            (Some(code.code), Some(code.expires_at))
        } else {
            (None, None)
        };

        created_licenses.push(CreatedLicense {
            id: license.id.clone(),
            activation_code,
            activation_code_expires_at,
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
            "license",
            &license.id,
            Some(
                &serde_json::json!({ "product_id": body.product_id, "expires_at": exps.license_exp, "has_email": email_hash.is_some() }),
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

    let license = queries::get_license_by_id(&conn, &path.license_id)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("License not found".into()));
    }

    let devices = queries::list_devices_for_license(&conn, &license.id)?;

    Ok(Json(LicenseWithDevices {
        license: LicenseWithProduct {
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

    let license = queries::get_license_by_id(&conn, &path.license_id)?
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

    queries::revoke_license(&conn, &license.id)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        &headers,
        "revoke_license",
        "license",
        &license.id,
        None,
        Some(&path.org_id),
        Some(&path.project_id),
    )?;

    Ok(Json(serde_json::json!({ "revoked": true })))
}

#[derive(Serialize)]
pub struct SendActivationCodeResponse {
    pub code: String,
    pub expires_at: i64,
    pub message: &'static str,
}

/// POST /orgs/{org_id}/projects/{project_id}/licenses/{license_id}/send-code
/// Generate an activation code for a license (for manual distribution to customer)
pub async fn send_activation_code(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<LicensePath>,
    headers: HeaderMap,
) -> Result<Json<SendActivationCodeResponse>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let license = queries::get_license_by_id(&conn, &path.license_id)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("License not found".into()));
    }

    if license.revoked {
        return Err(AppError::BadRequest("License is revoked".into()));
    }

    // Get project for activation code prefix
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    // Create activation code
    let code = queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        &headers,
        "generate_activation_code",
        "license",
        &license.id,
        Some(&serde_json::json!({ "expires_at": code.expires_at })),
        Some(&path.org_id),
        Some(&path.project_id),
    )?;

    Ok(Json(SendActivationCodeResponse {
        code: code.code,
        expires_at: code.expires_at,
        message: "Provide this code to the customer (expires in 30 minutes)",
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
    let license = queries::get_license_by_id(&conn, &path.license_id)?
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
            &serde_json::json!({ "license_id": license.id, "device_id": path.device_id, "device_name": device.name, "reason": "admin_remote_deactivation" }),
        ),
        Some(&path.org_id),
        Some(&path.project_id),
    )?;

    tracing::info!(
        "Device deactivated by admin: {} on license {} (project: {})",
        path.device_id,
        license.id,
        path.project_id
    );

    Ok(Json(DeactivateDeviceResponse {
        deactivated: true,
        device_id: path.device_id,
        remaining_devices: remaining,
    }))
}
