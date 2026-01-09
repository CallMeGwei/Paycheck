use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::Json;
use crate::models::CreateLicense;
use crate::util::LicenseExpirations;

#[derive(Debug, Deserialize)]
pub struct DevCreateLicense {
    pub product_id: String,
    /// Developer-managed customer identifier (optional)
    #[serde(default)]
    pub customer_id: Option<String>,
    /// Email for the license (optional - enables license recovery via email)
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct DevLicenseCreated {
    pub license_id: String,
    /// Activation code in PREFIX-XXXX-XXXX-XXXX-XXXX format (30 min TTL)
    pub activation_code: String,
    pub activation_code_expires_at: i64,
    pub product_id: String,
}

pub async fn create_dev_license(
    State(state): State<AppState>,
    Json(input): Json<DevCreateLicense>,
) -> Result<Json<DevLicenseCreated>> {
    let conn = state.db.get()?;

    // Verify product exists and get project for prefix
    let product = queries::get_product_by_id(&conn, &input.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    let project = queries::get_project_by_id(&conn, &product.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    // Compute expirations from product settings (input.expires_at can override)
    let now = chrono::Utc::now().timestamp();
    let exps = LicenseExpirations::from_product(&product, now);
    let expires_at = input.expires_at.or(exps.license_exp);

    // Compute email hash if email provided
    let email_hash = input.email.as_ref().map(|e| queries::hash_email(e));

    // Create the license (no payment info for dev licenses)
    let license = queries::create_license(
        &conn,
        &project.id,
        &input.product_id,
        &CreateLicense {
            email_hash,
            customer_id: input.customer_id.clone(),
            expires_at,
            updates_expires_at: exps.updates_exp,
            payment_provider: None,
            payment_provider_customer_id: None,
            payment_provider_subscription_id: None,
            payment_provider_order_id: None,
        },
    )?;

    // Create activation code for immediate use
    let activation_code =
        queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)?;

    tracing::info!(
        "DEV: Created test license {} for product {} ({})",
        license.id,
        product.name,
        input.product_id
    );

    Ok(Json(DevLicenseCreated {
        license_id: license.id,
        activation_code: activation_code.code,
        activation_code_expires_at: activation_code.expires_at,
        product_id: input.product_id,
    }))
}
