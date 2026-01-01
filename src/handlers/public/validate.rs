use axum::extract::State;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Query};
use crate::util::LicenseExpirations;

#[derive(Debug, Deserialize)]
pub struct ValidateQuery {
    pub project_id: String,
    pub jti: String,
}

#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updates_exp: Option<i64>,
}

pub async fn validate_license(
    State(state): State<AppState>,
    Query(query): Query<ValidateQuery>,
) -> Result<Json<ValidateResponse>> {
    let conn = state.db.get()?;

    // Find the device by JTI
    let device = match queries::get_device_by_jti(&conn, &query.jti)? {
        Some(d) => d,
        None => {
            return Ok(Json(ValidateResponse {
                valid: false,
                reason: Some("Token not found or already replaced".into()),
                license_exp: None,
                updates_exp: None,
            }));
        }
    };

    // Get the license
    let license = match queries::get_license_key_by_id(&conn, &device.license_key_id)? {
        Some(l) => l,
        None => {
            return Ok(Json(ValidateResponse {
                valid: false,
                reason: Some("License not found".into()),
                license_exp: None,
                updates_exp: None,
            }));
        }
    };

    // Check if license is revoked
    if license.revoked {
        return Ok(Json(ValidateResponse {
            valid: false,
            reason: Some("License has been revoked".into()),
            license_exp: None,
            updates_exp: None,
        }));
    }

    // Check if this specific JTI is revoked
    if license.revoked_jtis.contains(&query.jti) {
        return Ok(Json(ValidateResponse {
            valid: false,
            reason: Some("This token has been revoked".into()),
            license_exp: None,
            updates_exp: None,
        }));
    }

    // Check if license has expired
    if let Some(expires_at) = license.expires_at
        && Utc::now().timestamp() > expires_at
    {
        return Ok(Json(ValidateResponse {
            valid: false,
            reason: Some("License has expired".into()),
            license_exp: None,
            updates_exp: None,
        }));
    }

    // Get the product for expiration info
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::Internal("Product not found".into()))?;

    // Verify project matches
    if product.project_id != query.project_id {
        return Ok(Json(ValidateResponse {
            valid: false,
            reason: Some("Token not found".into()),
            license_exp: None,
            updates_exp: None,
        }));
    }

    // Update last seen
    queries::update_device_last_seen(&conn, &device.id)?;

    // Calculate current expirations based on activation time
    let exps = LicenseExpirations::from_product(&product, device.activated_at);

    // Check if license_exp has passed
    if let Some(exp) = exps.license_exp
        && Utc::now().timestamp() > exp
    {
        return Ok(Json(ValidateResponse {
            valid: false,
            reason: Some("License access has expired".into()),
            license_exp: Some(exp),
            updates_exp: exps.updates_exp,
        }));
    }

    Ok(Json(ValidateResponse {
        valid: true,
        reason: None,
        license_exp: exps.license_exp,
        updates_exp: exps.updates_exp,
    }))
}
