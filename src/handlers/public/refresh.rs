use axum::extract::State;
use axum::http::HeaderMap;
use chrono::Utc;
use serde::Serialize;

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::Json;
use crate::jwt::{self, LicenseClaims};
use crate::models::{ActorType, AuditAction, AuditLogNames};
use crate::util::{AuditLogBuilder, LicenseExpirations, extract_bearer_token};

/// Validate that a string is a valid UUID format.
/// This is a cheap check to reject garbage before hitting the database.
fn is_valid_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok()
}

#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub token: String,
}

/// Refresh an existing JWT to get a new token with updated expiration.
///
/// Accepts an existing JWT (even if expired) in the Authorization header.
/// Verifies the signature and JTI are valid, then issues a fresh JWT
/// with updated license_exp/updates_exp from the database.
///
/// This allows apps to get fresh tokens without storing the license key.
pub async fn refresh_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RefreshResponse>> {
    let token = extract_bearer_token(&headers).ok_or(AppError::Unauthorized)?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Decode without verification to get product_id for key lookup
    let unverified_claims = jwt::decode_unverified(token)?;

    // Validate product_id format before DB lookup (cheap DDoS protection)
    if !is_valid_uuid(&unverified_claims.product_id) {
        return Err(AppError::Unauthorized);
    }

    // Look up the product and project
    let product = queries::get_product_by_id(&conn, &unverified_claims.product_id)?
        .ok_or(AppError::Unauthorized)?;

    let project =
        queries::get_project_by_id(&conn, &product.project_id)?.ok_or(AppError::Unauthorized)?;

    // Now verify the token signature (allowing expired tokens)
    let verified = jwt::verify_token_allow_expired(token, &project.public_key)
        .map_err(|_| AppError::Unauthorized)?;

    let jti = verified.jwt_id.ok_or(AppError::Unauthorized)?;

    // Validate JTI format before DB lookup (cheap DDoS protection)
    if !is_valid_uuid(&jti) {
        return Err(AppError::Unauthorized);
    }

    // Look up the device by JTI
    let device = queries::get_device_by_jti(&conn, &jti)?.ok_or(AppError::Unauthorized)?;

    // Get the license
    let license =
        queries::get_license_by_id(&conn, &device.license_id)?.ok_or(AppError::Unauthorized)?;

    // Check if license is revoked
    if license.revoked {
        return Err(AppError::Unauthorized);
    }

    // Check if this specific JTI is revoked
    if queries::is_jti_revoked(&conn, &license.id, &jti)? {
        return Err(AppError::Unauthorized);
    }

    // Check if license has expired (database-level expiration, not JWT exp)
    if let Some(expires_at) = license.expires_at
        && Utc::now().timestamp() > expires_at
    {
        return Err(AppError::Unauthorized);
    }

    // Update last_seen_at
    queries::update_device_last_seen(&conn, &device.id)?;

    // Calculate fresh expirations from current database values
    let now = Utc::now().timestamp();
    let exps = LicenseExpirations::from_product(&product, device.activated_at);

    // Check if license_exp has passed
    if let Some(exp) = exps.license_exp
        && now > exp
    {
        return Err(AppError::Unauthorized);
    }

    // Build new claims with updated expirations
    let claims = LicenseClaims {
        license_exp: exps.license_exp,
        updates_exp: exps.updates_exp,
        tier: product.tier.clone(),
        features: product.features.clone(),
        device_id: device.device_id.clone(),
        device_type: match device.device_type {
            crate::models::DeviceType::Uuid => "uuid".to_string(),
            crate::models::DeviceType::Machine => "machine".to_string(),
        },
        product_id: product.id.clone(),
    };

    // Sign new JWT
    let private_key = state
        .master_key
        .decrypt_private_key(&project.id, &project.private_key)?;
    let new_token = jwt::sign_claims(&claims, &private_key, &license.id, &project.name, &jti)?;

    // Audit log the refresh
    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::Public, None)
        .action(AuditAction::RefreshToken)
        .resource("device", &device.id)
        .details(
            &serde_json::json!({ "license_id": license.id, "product_id": product.id, "jti": jti }),
        )
        .org(&project.org_id)
        .project(&project.id)
        .names(&AuditLogNames {
            resource_name: device.name.clone(),
            project_name: Some(project.name.clone()),
            ..Default::default()
        })
        .save()?;

    Ok(Json(RefreshResponse { token: new_token }))
}
