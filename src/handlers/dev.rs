use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::Json;
use crate::models::CreateLicenseKey;
use crate::util::LicenseExpirations;

#[derive(Debug, Deserialize)]
pub struct DevCreateLicense {
    pub product_id: String,
    /// Developer-managed customer identifier (optional)
    #[serde(default)]
    pub customer_id: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct DevLicenseCreated {
    pub license_id: String,
    pub license_key: String,
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

    // Create the license with project's prefix (no payment info for dev licenses)
    let license = queries::create_license_key(
        &conn,
        &input.product_id,
        &project.license_key_prefix,
        &CreateLicenseKey {
            customer_id: input.customer_id.clone(),
            expires_at,
            updates_expires_at: exps.updates_exp,
            payment_provider: None,
            payment_provider_customer_id: None,
            payment_provider_subscription_id: None,
            payment_provider_order_id: None,
        },
    )?;

    tracing::info!(
        "DEV: Created test license {} for product {} ({})",
        license.key,
        product.name,
        input.product_id
    );

    Ok(Json(DevLicenseCreated {
        license_id: license.id,
        license_key: license.key,
        product_id: input.product_id,
    }))
}
