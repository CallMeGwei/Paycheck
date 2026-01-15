use axum::extract::State;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::MasterKey;
use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::Json;
use crate::jwt::{self, LicenseClaims};
use crate::models::DeviceType;
use crate::util::LicenseExpirations;

// Input length limits to prevent storage exhaustion and oversized JWTs
const MAX_PUBLIC_KEY_LEN: usize = 256;
const MAX_CODE_LEN: usize = 64;
const MAX_DEVICE_ID_LEN: usize = 256;
const MAX_DEVICE_NAME_LEN: usize = 256;

/// Request body for POST /redeem (using short-lived activation code)
#[derive(Debug, Deserialize)]
pub struct RedeemRequest {
    /// Public key - identifies the project
    pub public_key: String,
    /// Short-lived activation code (PREFIX-XXXX-XXXX-XXXX-XXXX format)
    pub code: String,
    pub device_id: String,
    pub device_type: String,
    #[serde(default)]
    pub device_name: Option<String>,
}

impl RedeemRequest {
    /// Validate input lengths to prevent storage exhaustion attacks.
    fn validate(&self) -> Result<()> {
        if self.public_key.len() > MAX_PUBLIC_KEY_LEN {
            return Err(AppError::BadRequest(format!(
                "public_key too long (max {} chars)",
                MAX_PUBLIC_KEY_LEN
            )));
        }
        if self.code.len() > MAX_CODE_LEN {
            return Err(AppError::BadRequest(format!(
                "code too long (max {} chars)",
                MAX_CODE_LEN
            )));
        }
        if self.device_id.is_empty() {
            return Err(AppError::BadRequest("device_id cannot be empty".into()));
        }
        if self.device_id.len() > MAX_DEVICE_ID_LEN {
            return Err(AppError::BadRequest(format!(
                "device_id too long (max {} chars)",
                MAX_DEVICE_ID_LEN
            )));
        }
        if let Some(ref name) = self.device_name
            && name.len() > MAX_DEVICE_NAME_LEN
        {
            return Err(AppError::BadRequest(format!(
                "device_name too long (max {} chars)",
                MAX_DEVICE_NAME_LEN
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct RedeemResponse {
    pub token: String,
    pub license_exp: Option<i64>,
    pub updates_exp: Option<i64>,
    pub tier: String,
    pub features: Vec<String>,
    /// Short-lived activation code for future activations
    pub activation_code: String,
    /// Expiration time of the activation code
    pub activation_code_expires_at: i64,
}

/// POST /redeem - Redeem using a short-lived activation code
///
/// The activation code is in PREFIX-XXXX-XXXX-XXXX-XXXX format and expires after 30 minutes.
/// After successful redemption, a fresh activation code is returned for future use.
pub async fn redeem_with_code(
    State(state): State<AppState>,
    Json(req): Json<RedeemRequest>,
) -> Result<Json<RedeemResponse>> {
    // Validate input lengths first (cheap check before any DB operations)
    req.validate()?;

    let mut conn = state.db.get()?;

    // Look up project by public key
    let project = queries::get_project_by_public_key(&conn, &req.public_key)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;
    let project_id = project.id;

    // Validate device type
    let device_type = req.device_type.parse::<DeviceType>().ok().ok_or_else(|| {
        AppError::BadRequest("Invalid device_type. Must be 'uuid' or 'machine'".into())
    })?;

    // Atomically claim the activation code (prevents race conditions where multiple
    // concurrent requests could use the same code to create multiple devices)
    let activation_code = queries::try_claim_activation_code(&conn, &req.code)?
        .ok_or_else(|| AppError::Forbidden("Cannot be redeemed".into()))?;

    // Get the license
    let license = queries::get_license_by_id(&conn, &activation_code.license_id)?
        .ok_or_else(|| AppError::Internal("License not found".into()))?;

    // Proceed with normal redemption logic
    redeem_license_internal(
        &mut conn,
        &state.master_key,
        &license,
        &project_id,
        &req.device_id,
        device_type,
        req.device_name.as_deref(),
    )
}

/// Internal function that handles the actual license redemption logic
fn redeem_license_internal(
    conn: &mut r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>,
    master_key: &MasterKey,
    license: &crate::models::License,
    project_id: &str,
    device_id: &str,
    device_type: DeviceType,
    device_name: Option<&str>,
) -> Result<Json<RedeemResponse>> {
    // Check if revoked or expired (generic message to prevent enumeration)
    let is_expired = license
        .expires_at
        .is_some_and(|exp| Utc::now().timestamp() > exp);
    if license.revoked || is_expired {
        return Err(AppError::Forbidden("Cannot be redeemed".into()));
    }

    // Get the product
    let product = queries::get_product_by_id(conn, &license.product_id)?
        .ok_or_else(|| AppError::Internal("Product not found".into()))?;

    // Verify project matches
    if product.project_id != project_id {
        return Err(AppError::NotFound("License not found".into()));
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
    };

    // Decrypt the private key and sign the JWT
    let private_key = master_key.decrypt_private_key(&project.id, &project.private_key)?;
    let token = jwt::sign_claims(&claims, &private_key, &license.id, &project.name, &jti)?;

    // Create a fresh activation code for future activations (e.g., on new device)
    let new_activation_code =
        queries::create_activation_code(conn, &license.id, &project.license_key_prefix)?;

    Ok(Json(RedeemResponse {
        token,
        license_exp: exps.license_exp,
        updates_exp: exps.updates_exp,
        tier: product.tier,
        features: product.features,
        activation_code: new_activation_code.code,
        activation_code_expires_at: new_activation_code.expires_at,
    }))
}
