use axum::extract::State;
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use serde::Serialize;

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::Json;
use crate::jwt;

#[derive(Debug, Serialize)]
pub struct DeactivateResponse {
    pub deactivated: bool,
    pub remaining_devices: i32,
}

/// POST /devices/deactivate - Self-deactivation
/// Requires JWT in Authorization header - device can only deactivate itself
/// For remote deactivation of lost devices, use the org admin API
pub async fn deactivate_device(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<DeactivateResponse>> {
    let conn = state.db.get()?;
    let token = auth.token();

    // First, decode the token without verification to get the product_id
    // We need this to look up the project and its public key
    let unverified_claims = jwt::decode_unverified(token)?;

    // Look up the product to get the project
    let product = queries::get_product_by_id(&conn, &unverified_claims.product_id)?
        .ok_or_else(|| AppError::BadRequest("Invalid token: product not found".into()))?;

    // Get the project to get the public key
    let project = queries::get_project_by_id(&conn, &product.project_id)?
        .ok_or_else(|| AppError::Internal("Project not found".into()))?;

    // Now verify the JWT signature with the project's public key
    // Also validates issuer ("paycheck") and audience (project.domain)
    let verified_claims = jwt::verify_token(token, &project.public_key, &project.domain)?;

    // Extract JTI from verified claims
    let jti = verified_claims
        .jwt_id
        .ok_or_else(|| AppError::BadRequest("Invalid token: missing jti".into()))?;

    // Look up the device by JTI
    let device = queries::get_device_by_jti(&conn, &jti)?
        .ok_or_else(|| AppError::NotFound("Device not found or already deactivated".into()))?;

    // Get the license to add revoked JTI
    let license = queries::get_license_key_by_id(&conn, &device.license_key_id, &state.master_key)?
        .ok_or_else(|| AppError::Internal("License not found".into()))?;

    // Check if this JTI is already revoked
    if license.revoked_jtis.contains(&jti) {
        return Err(AppError::Forbidden("This device has already been deactivated".into()));
    }

    // Add the device's JTI to revoked list so the token can't be used anymore
    queries::add_revoked_jti(&conn, &license.id, &jti, &state.master_key)?;

    // Delete the device record
    queries::delete_device(&conn, &device.id)?;

    // Get remaining device count
    let remaining = queries::count_devices_for_license(&conn, &license.id)?;

    Ok(Json(DeactivateResponse {
        deactivated: true,
        remaining_devices: remaining,
    }))
}
