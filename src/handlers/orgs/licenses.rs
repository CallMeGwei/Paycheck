use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, AuditAction, CreateLicense, Device, LicenseWithProduct};
use crate::pagination::Paginated;
use crate::util::{AuditLogBuilder, LicenseExpirations};

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
    /// Filter by payment provider order ID (for support lookups via receipt)
    pub payment_provider_order_id: Option<String>,
    /// Max results to return (default 50, max 100)
    pub limit: Option<i64>,
    /// Offset for pagination (default 0)
    pub offset: Option<i64>,
}

impl ListLicensesQuery {
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(50).clamp(1, 100)
    }

    fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }
}

/// GET /orgs/{org_id}/projects/{project_id}/licenses
/// List licenses for a project with pagination, optionally filtered by email or payment order ID.
/// When filtering by email or order ID, returns ALL licenses including expired/revoked (for support).
pub async fn list_licenses(
    State(state): State<AppState>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    Query(query): Query<ListLicensesQuery>,
) -> Result<Json<Paginated<LicenseWithProduct>>> {
    let conn = state.db.get()?;

    let limit = query.limit();
    let offset = query.offset();

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
    } else if let Some(ref order_id) = query.payment_provider_order_id {
        // Support lookup by payment provider order ID (e.g., from receipt) - includes expired/revoked
        queries::get_licenses_by_payment_order_id_paginated(
            &conn,
            &path.project_id,
            order_id,
            limit,
            offset,
        )?
    } else {
        // Default: list all licenses for project
        queries::list_licenses_for_project_paginated(&conn, &path.project_id, limit, offset)?
    };

    Ok(Json(Paginated::new(licenses, total, limit, offset)))
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
        AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
            .actor(ActorType::User, Some(&ctx.member.user_id))
            .action(AuditAction::CreateLicense)
            .resource("license", &license.id)
            .details(&serde_json::json!({ "product_id": body.product_id, "expires_at": exps.license_exp, "has_email": email_hash.is_some() }))
            .org(&path.org_id)
            .project(&path.project_id)
            .names(&ctx.audit_names().project(project.name.clone()))
            .save()?;
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

/// Request body for updating a license (email correction)
#[derive(Debug, Deserialize)]
pub struct UpdateLicenseBody {
    /// New email to hash and store (fixes typo'd purchase email)
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateLicenseResponse {
    #[serde(flatten)]
    pub license: LicenseWithProduct,
    pub message: &'static str,
}

/// PATCH /orgs/{org_id}/projects/{project_id}/licenses/{license_id}
/// Update a license's email hash to fix typo'd purchase emails.
/// This enables self-service recovery with the corrected email address.
pub async fn update_license(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<LicensePath>,
    headers: HeaderMap,
    Json(body): Json<UpdateLicenseBody>,
) -> Result<Json<UpdateLicenseResponse>> {
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

    // Fetch project for audit log context
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    // Update email hash if provided
    if let Some(ref email) = body.email {
        let new_email_hash = queries::hash_email(email);
        queries::update_license_email_hash(&conn, &license.id, &new_email_hash)?;

        // Audit log the email change (log old hash for investigation, not new email for privacy)
        AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
            .actor(ActorType::User, Some(&ctx.member.user_id))
            .action(AuditAction::UpdateLicenseEmail)
            .resource("license", &license.id)
            .details(&serde_json::json!({
                "old_email_hash": license.email_hash,
                "reason": "email_correction"
            }))
            .org(&path.org_id)
            .project(&path.project_id)
            .names(&ctx.audit_names().project(project.name.clone()))
            .save()?;

        tracing::info!(
            "License email updated by admin: {} (project: {})",
            license.id,
            path.project_id
        );
    }

    // Fetch the updated license
    let updated_license = queries::get_license_by_id(&conn, &path.license_id)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    Ok(Json(UpdateLicenseResponse {
        license: LicenseWithProduct {
            license: updated_license,
            product_name: product.name,
        },
        message: "License email updated. Customer can now use self-service recovery with the new email.",
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

    // Fetch project for audit log context
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    queries::revoke_license(&conn, &license.id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::RevokeLicense)
        .resource("license", &license.id)
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().project(project.name.clone()))
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
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

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::GenerateActivationCode)
        .resource("license", &license.id)
        .details(&serde_json::json!({ "expires_at": code.expires_at }))
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().project(project.name.clone()))
        .save()?;

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
    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::DeactivateDevice)
        .resource("device", &device.id)
        .details(&serde_json::json!({ "license_id": license.id, "device_id": path.device_id, "device_name": device.name, "reason": "admin_remote_deactivation" }))
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().resource(device.name.clone()))
        .save()?;

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
