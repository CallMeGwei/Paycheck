use axum::extract::State;
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, OptionExt, Result, msg};
use crate::extractors::{Json, Query};
use crate::jwt;

/// Query parameters for GET /license
#[derive(Debug, Deserialize)]
pub struct LicenseQuery {
    /// Public key - identifies the project
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct LicenseDeviceInfo {
    pub device_id: String,
    pub device_type: String,
    pub name: Option<String>,
    pub activated_at: i64,
    pub last_seen_at: i64,
}

#[derive(Debug, Serialize)]
pub struct LicenseResponse {
    pub status: LicenseStatus,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub updates_expires_at: Option<i64>,
    pub activation_count: i32,
    /// None = unlimited
    pub activation_limit: Option<i32>,
    pub device_count: i32,
    /// None = unlimited
    pub device_limit: Option<i32>,
    pub devices: Vec<LicenseDeviceInfo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatus {
    Active,
    Expired,
    Revoked,
}

/// GET /license - Get license info
/// JWT token in Authorization header, public_key in query
pub async fn get_license_info(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<LicenseQuery>,
) -> Result<Json<LicenseResponse>> {
    let conn = state.db.get()?;
    let token = auth.token();

    // Look up project by public key (validates project exists)
    let _project = queries::get_project_by_public_key(&conn, &query.public_key)?
        .or_not_found(msg::PROJECT_NOT_FOUND)?;

    // Verify JWT signature (allow expired JWTs - we just need identity)
    let claims = jwt::verify_token_allow_expired(token, &query.public_key)?;

    // Extract JTI from verified token
    let jti = claims
        .jwt_id
        .ok_or_else(|| AppError::BadRequest(msg::TOKEN_MISSING_JTI.into()))?;

    // Look up device by JTI
    let device = queries::get_device_by_jti(&conn, &jti)?.or_not_found(msg::DEVICE_NOT_FOUND)?;

    // Get license from device
    let license = queries::get_license_by_id(&conn, &device.license_id)?
        .or_not_found(msg::LICENSE_NOT_FOUND)?;

    // Check if this JTI is revoked
    if queries::is_jti_revoked(&conn, &jti)? {
        return Err(AppError::Forbidden(msg::DEVICE_DEACTIVATED.into()));
    }

    // Get the product for limits
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::Internal(msg::PRODUCT_NOT_FOUND.into()))?;

    // Determine status
    let now = chrono::Utc::now().timestamp();
    let status = if license.revoked {
        LicenseStatus::Revoked
    } else if license.expires_at.map(|exp| exp < now).unwrap_or(false) {
        LicenseStatus::Expired
    } else {
        LicenseStatus::Active
    };

    // Get all devices for this license
    let devices = queries::list_devices_for_license(&conn, &license.id)?;
    let device_count = devices.len() as i32;

    let device_infos: Vec<LicenseDeviceInfo> = devices
        .into_iter()
        .map(|d| LicenseDeviceInfo {
            device_id: d.device_id,
            device_type: match d.device_type {
                crate::models::DeviceType::Uuid => "uuid".to_string(),
                crate::models::DeviceType::Machine => "machine".to_string(),
            },
            name: d.name,
            activated_at: d.activated_at,
            last_seen_at: d.last_seen_at,
        })
        .collect();

    Ok(Json(LicenseResponse {
        status,
        created_at: license.created_at,
        expires_at: license.expires_at,
        updates_expires_at: license.updates_expires_at,
        activation_count: license.activation_count,
        activation_limit: product.activation_limit,
        device_count,
        device_limit: product.device_limit,
        devices: device_infos,
    }))
}
