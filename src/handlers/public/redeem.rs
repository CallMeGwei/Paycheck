use axum::{extract::State, http::HeaderMap};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::MasterKey;
use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Query};
use crate::jwt::{self, LicenseClaims};
use crate::models::DeviceType;
use crate::util::{extract_bearer_token, LicenseExpirations};

/// Query parameters for GET /redeem (using short-lived redemption code)
#[derive(Debug, Deserialize)]
pub struct RedeemCodeQuery {
    pub project_id: String,
    /// Short-lived redemption code (not the permanent license key)
    pub code: String,
    pub device_id: String,
    pub device_type: String,
    #[serde(default)]
    pub device_name: Option<String>,
}

/// Request body for POST /redeem/key (using permanent license key)
#[derive(Debug, Deserialize)]
pub struct RedeemKeyBody {
    pub project_id: String,
    /// Permanent license key - can be in body OR Authorization header
    #[serde(default)]
    pub key: Option<String>,
    pub device_id: String,
    pub device_type: String,
    #[serde(default)]
    pub device_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RedeemResponse {
    pub token: String,
    pub license_exp: Option<i64>,
    pub updates_exp: Option<i64>,
    pub tier: String,
    pub features: Vec<String>,
    /// Short-lived redemption code for future URL-based redemptions
    pub redemption_code: String,
    /// Expiration time of the redemption code
    pub redemption_code_expires_at: i64,
}

/// GET /redeem - Redeem using a short-lived redemption code
/// The redemption code is safe to appear in URLs as it expires quickly
pub async fn redeem_with_code(
    State(state): State<AppState>,
    Query(query): Query<RedeemCodeQuery>,
) -> Result<Json<RedeemResponse>> {
    let mut conn = state.db.get()?;

    // Validate device type
    let device_type = query.device_type.parse::<DeviceType>()
        .ok().ok_or_else(|| AppError::BadRequest("Invalid device_type. Must be 'uuid' or 'machine'".into()))?;

    // Look up the redemption code
    let redemption_code = queries::get_redemption_code_by_code(&conn, &query.code)?
        .ok_or_else(|| AppError::NotFound("Redemption code not found or expired".into()))?;

    // Check if already used
    if redemption_code.used {
        return Err(AppError::Forbidden("Redemption code has already been used".into()));
    }

    // Check if expired
    if Utc::now().timestamp() > redemption_code.expires_at {
        return Err(AppError::Forbidden("Redemption code has expired".into()));
    }

    // Get the license key
    let license = queries::get_license_key_by_id(&conn, &redemption_code.license_key_id, &state.master_key)?
        .ok_or_else(|| AppError::Internal("License key not found".into()))?;

    // Mark redemption code as used
    queries::mark_redemption_code_used(&conn, &redemption_code.id)?;

    // Proceed with normal redemption logic
    redeem_license_internal(
        &mut conn,
        &state.master_key,
        &license,
        &query.project_id,
        &query.device_id,
        device_type,
        query.device_name.as_deref(),
    )
}

/// POST /redeem/key - Redeem using the permanent license key
///
/// License key can be provided via:
/// - Authorization header: `Authorization: Bearer {key}`
/// - Request body: `{"key": "..."}`
///
/// Header takes precedence if both are provided.
pub async fn redeem_with_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RedeemKeyBody>,
) -> Result<Json<RedeemResponse>> {
    let mut conn = state.db.get()?;

    // Extract key from header first, fall back to body
    let key = extract_bearer_token(&headers)
        .map(String::from)
        .or(body.key)
        .ok_or_else(|| AppError::BadRequest(
            "License key required. Provide via Authorization header (Bearer {key}) or request body.".into()
        ))?;

    // Validate device type
    let device_type = body.device_type.parse::<DeviceType>()
        .ok().ok_or_else(|| AppError::BadRequest("Invalid device_type. Must be 'uuid' or 'machine'".into()))?;

    // Get the license key
    let license = queries::get_license_key_by_key(&conn, &key, &state.master_key)?
        .ok_or_else(|| AppError::NotFound("License key not found".into()))?;

    // Proceed with normal redemption logic
    redeem_license_internal(
        &mut conn,
        &state.master_key,
        &license,
        &body.project_id,
        &body.device_id,
        device_type,
        body.device_name.as_deref(),
    )
}

/// Internal function that handles the actual license redemption logic
fn redeem_license_internal(
    conn: &mut r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>,
    master_key: &MasterKey,
    license: &crate::models::LicenseKey,
    project_id: &str,
    device_id: &str,
    device_type: DeviceType,
    device_name: Option<&str>,
) -> Result<Json<RedeemResponse>> {
    // Check if revoked
    if license.revoked {
        return Err(AppError::Forbidden("License has been revoked".into()));
    }

    // Check if expired
    if let Some(expires_at) = license.expires_at
        && Utc::now().timestamp() > expires_at
    {
        return Err(AppError::Forbidden("License has expired".into()));
    }

    // Get the product
    let product = queries::get_product_by_id(conn, &license.product_id)?
        .ok_or_else(|| AppError::Internal("Product not found".into()))?;

    // Verify project matches
    if product.project_id != project_id {
        return Err(AppError::NotFound("License key not found".into()));
    }

    // Get the project for signing
    let project = queries::get_project_by_id(conn, project_id)?
        .ok_or_else(|| AppError::Internal("Project not found".into()))?;

    // Generate JTI for the new token
    let jti = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();

    // Atomically acquire device (handles limit checks + creation in a transaction)
    // This prevents race conditions where concurrent requests could bypass device limits
    let _device = queries::acquire_device_atomic(
        conn,
        &license.id,
        device_id,
        device_type,
        &jti,
        device_name,
        product.device_limit,
        product.activation_limit,
    )?;

    // Calculate expirations
    let exps = LicenseExpirations::from_product(&product, now);

    // Build claims
    let claims = LicenseClaims {
        license_exp: exps.license_exp,
        updates_exp: exps.updates_exp,
        tier: product.tier.clone(),
        features: product.features.clone(),
        device_id: device_id.to_string(),
        device_type: match device_type {
            DeviceType::Uuid => "uuid".to_string(),
            DeviceType::Machine => "machine".to_string(),
        },
        product_id: product.id.clone(),
        license_key: license.key.clone(),
    };

    // Decrypt the private key and sign the JWT
    let private_key = master_key.decrypt_private_key(&project.id, &project.private_key)?;
    let token = jwt::sign_claims(
        &claims,
        &private_key,
        &license.id,
        &project.domain,
        &jti,
    )?;

    // Create a fresh redemption code for future URL-based redemptions
    let new_redemption_code = queries::create_redemption_code(conn, &license.id)?;

    Ok(Json(RedeemResponse {
        token,
        license_exp: exps.license_exp,
        updates_exp: exps.updates_exp,
        tier: product.tier,
        features: product.features,
        redemption_code: new_redemption_code.code,
        redemption_code_expires_at: new_redemption_code.expires_at,
    }))
}

/// POST /redeem/code - Generate a new redemption code from a license key
/// This allows users to get a URL-safe code without exposing their license key
/// License key can be provided via:
///   - Authorization header: `Authorization: Bearer {key}`
///   - Request body: `{"key": "..."}`
#[derive(Debug, Deserialize, Default)]
pub struct GenerateCodeBody {
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GenerateCodeResponse {
    pub code: String,
    pub expires_at: i64,
}

pub async fn generate_redemption_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GenerateCodeBody>,
) -> Result<Json<GenerateCodeResponse>> {
    let conn = state.db.get()?;

    // Extract key from header first, fall back to body
    let key = extract_bearer_token(&headers)
        .map(String::from)
        .or(body.key)
        .ok_or_else(|| AppError::BadRequest(
            "License key required. Provide via Authorization header (Bearer {key}) or request body.".into()
        ))?;

    // Get the license key
    let license = queries::get_license_key_by_key(&conn, &key, &state.master_key)?
        .ok_or_else(|| AppError::NotFound("License key not found".into()))?;

    // Check if revoked
    if license.revoked {
        return Err(AppError::Forbidden("License has been revoked".into()));
    }

    // Check if expired
    if let Some(expires_at) = license.expires_at
        && Utc::now().timestamp() > expires_at
    {
        return Err(AppError::Forbidden("License has expired".into()));
    }

    // Create a new redemption code
    let redemption_code = queries::create_redemption_code(&conn, &license.id)?;

    Ok(Json(GenerateCodeResponse {
        code: redemption_code.code,
        expires_at: redemption_code.expires_at,
    }))
}
