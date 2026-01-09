use axum::extract::State;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Query};
use crate::util::LicenseExpirations;

#[derive(Debug, Deserialize)]
pub struct ValidateQuery {
    /// Public key - identifies the project (preferred)
    #[serde(default)]
    pub public_key: Option<String>,
    /// Project ID - deprecated, use public_key instead
    #[serde(default)]
    pub project_id: Option<String>,
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

    // Helper for invalid responses - no reason given to prevent information disclosure
    let invalid_response = || {
        Json(ValidateResponse {
            valid: false,
            reason: None,
            license_exp: None,
            updates_exp: None,
        })
    };

    // Resolve project ID from public_key or project_id
    let project_id = if let Some(ref public_key) = query.public_key {
        let project = queries::get_project_by_public_key(&conn, public_key)?;
        match project {
            Some(p) => p.id,
            None => return Ok(invalid_response()),
        }
    } else if let Some(ref project_id) = query.project_id {
        project_id.clone()
    } else {
        return Err(AppError::BadRequest(
            "Either public_key or project_id is required".into(),
        ));
    };

    // Find the device by JTI
    let device = match queries::get_device_by_jti(&conn, &query.jti)? {
        Some(d) => d,
        None => return Ok(invalid_response()),
    };

    // Get the license
    let license = match queries::get_license_by_id(&conn, &device.license_id)? {
        Some(l) => l,
        None => return Ok(invalid_response()),
    };

    // Check if license is revoked
    if license.revoked {
        return Ok(invalid_response());
    }

    // Check if this specific JTI is revoked
    if license.revoked_jtis.contains(&query.jti) {
        return Ok(invalid_response());
    }

    // Check if license has expired
    if let Some(expires_at) = license.expires_at
        && Utc::now().timestamp() > expires_at
    {
        return Ok(invalid_response());
    }

    // Get the product for expiration info
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::Internal("Product not found".into()))?;

    // Verify project matches
    if product.project_id != project_id {
        return Ok(invalid_response());
    }

    // Update last seen
    queries::update_device_last_seen(&conn, &device.id)?;

    // Calculate current expirations based on activation time
    let exps = LicenseExpirations::from_product(&product, device.activated_at);

    // Check if license_exp has passed
    if let Some(exp) = exps.license_exp
        && Utc::now().timestamp() > exp
    {
        return Ok(invalid_response());
    }

    Ok(Json(ValidateResponse {
        valid: true,
        reason: None,
        license_exp: exps.license_exp,
        updates_exp: exps.updates_exp,
    }))
}
