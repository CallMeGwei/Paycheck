use axum::{
    extract::{Query, State},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{queries, DbPool};
use crate::error::{AppError, Result};
use crate::jwt::{self, LicenseClaims};
use crate::models::DeviceType;

#[derive(Debug, Deserialize)]
pub struct RedeemQuery {
    pub project_id: String,
    pub key: String,
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
}

pub async fn redeem_license(
    State(pool): State<DbPool>,
    Query(query): Query<RedeemQuery>,
) -> Result<Json<RedeemResponse>> {
    let conn = pool.get()?;

    // Validate device type
    let device_type = DeviceType::from_str(&query.device_type)
        .ok_or_else(|| AppError::BadRequest("Invalid device_type. Must be 'uuid' or 'machine'".into()))?;

    // Get the license key
    let license = queries::get_license_key_by_key(&conn, &query.key)?
        .ok_or_else(|| AppError::NotFound("License key not found".into()))?;

    // Check if revoked
    if license.revoked {
        return Err(AppError::Forbidden("License has been revoked".into()));
    }

    // Check if expired
    if let Some(expires_at) = license.expires_at {
        if Utc::now().timestamp() > expires_at {
            return Err(AppError::Forbidden("License has expired".into()));
        }
    }

    // Get the product
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::Internal("Product not found".into()))?;

    // Verify project matches
    if product.project_id != query.project_id {
        return Err(AppError::NotFound("License key not found".into()));
    }

    // Get the project for signing
    let project = queries::get_project_by_id(&conn, &query.project_id)?
        .ok_or_else(|| AppError::Internal("Project not found".into()))?;

    // Check device limit
    let current_device_count = queries::count_devices_for_license(&conn, &license.id)?;
    let existing_device = queries::get_device_for_license(&conn, &license.id, &query.device_id)?;

    if existing_device.is_none() && product.device_limit > 0 && current_device_count >= product.device_limit {
        return Err(AppError::Forbidden(format!(
            "Device limit reached ({}/{}). Deactivate a device first.",
            current_device_count, product.device_limit
        )));
    }

    // Check activation limit (only for new devices)
    if existing_device.is_none() && product.activation_limit > 0 && license.activation_count >= product.activation_limit {
        return Err(AppError::Forbidden(format!(
            "Activation limit reached ({}/{})",
            license.activation_count, product.activation_limit
        )));
    }

    // Generate JTI
    let jti = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();

    // Calculate expirations
    let license_exp = product.license_exp_days.map(|days| now + (days as i64 * 86400));
    let updates_exp = product.updates_exp_days.map(|days| now + (days as i64 * 86400));

    // Build claims
    let claims = LicenseClaims {
        license_exp,
        updates_exp,
        tier: product.tier.clone(),
        features: product.features.clone(),
        device_id: query.device_id.clone(),
        device_type: query.device_type.clone(),
        email: license.email.clone(),
        product_id: product.id.clone(),
        license_key: license.key.clone(),
    };

    // Sign the JWT
    let token = jwt::sign_claims(
        &claims,
        &project.private_key,
        &license.id,
        &project.domain,
        &jti,
    )?;

    // Update or create device record
    if let Some(existing) = existing_device {
        // Update existing device with new JTI
        queries::update_device_jti(&conn, &existing.id, &jti)?;
    } else {
        // Create new device
        queries::create_device(
            &conn,
            &license.id,
            &query.device_id,
            device_type,
            &jti,
            query.device_name.as_deref(),
        )?;

        // Increment activation count
        queries::increment_activation_count(&conn, &license.id)?;
    }

    Ok(Json(RedeemResponse {
        token,
        license_exp,
        updates_exp,
        tier: product.tier,
        features: product.features,
    }))
}
