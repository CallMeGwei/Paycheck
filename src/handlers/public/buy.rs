use axum::{
    extract::{Query, State},
    response::Redirect,
};
use serde::Deserialize;

use crate::db::{queries, DbPool};
use crate::error::{AppError, Result};
use crate::models::{CreatePaymentSession, DeviceType};
use crate::payments::{LemonSqueezyClient, PaymentProvider, StripeClient};

#[derive(Debug, Deserialize)]
pub struct BuyQuery {
    pub project_id: String,
    pub product_id: String,
    pub device_id: String,
    pub device_type: String,
    #[serde(default)]
    pub provider: Option<String>,
    /// Stripe: price in cents; LemonSqueezy: variant ID
    #[serde(default)]
    pub variant_id: Option<String>,
    #[serde(default)]
    pub price_cents: Option<u64>,
    #[serde(default)]
    pub currency: Option<String>,
}

pub async fn initiate_buy(
    State(pool): State<DbPool>,
    Query(query): Query<BuyQuery>,
) -> Result<Redirect> {
    let conn = pool.get()?;

    // Validate device type
    let device_type = DeviceType::from_str(&query.device_type)
        .ok_or_else(|| AppError::BadRequest("Invalid device_type".into()))?;

    // Get project
    let project = queries::get_project_by_id(&conn, &query.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    // Get product
    let product = queries::get_product_by_id(&conn, &query.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    // Verify product belongs to project
    if product.project_id != query.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    // Determine payment provider
    let provider = if let Some(ref p) = query.provider {
        PaymentProvider::from_str(p)
            .ok_or_else(|| AppError::BadRequest("Invalid provider".into()))?
    } else {
        // Default: prefer Stripe, fallback to LemonSqueezy
        if project.stripe_config.is_some() {
            PaymentProvider::Stripe
        } else if project.ls_config.is_some() {
            PaymentProvider::LemonSqueezy
        } else {
            return Err(AppError::BadRequest("No payment provider configured".into()));
        }
    };

    // Create payment session
    let session = queries::create_payment_session(
        &conn,
        &CreatePaymentSession {
            product_id: query.product_id.clone(),
            device_id: query.device_id.clone(),
            device_type,
        },
    )?;

    // Build callback URL (the payment provider will redirect here after success)
    // In production, this should be configured via environment variable
    let base_url = std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let callback_url = format!("{}/callback?session={}", base_url, session.id);
    let cancel_url = format!("{}/cancel", base_url);

    // Create checkout with the appropriate provider
    let checkout_url = match provider {
        PaymentProvider::Stripe => {
            let config = project.stripe_config
                .ok_or_else(|| AppError::BadRequest("Stripe not configured".into()))?;

            let price_cents = query.price_cents
                .ok_or_else(|| AppError::BadRequest("price_cents required for Stripe".into()))?;
            let currency = query.currency.as_deref().unwrap_or("usd");

            let client = StripeClient::new(&config);
            let (_, url) = client
                .create_checkout_session(
                    &session.id,
                    &query.project_id,
                    &query.product_id,
                    &product.name,
                    price_cents,
                    currency,
                    &callback_url,
                    &cancel_url,
                )
                .await?;
            url
        }
        PaymentProvider::LemonSqueezy => {
            let config = project.ls_config
                .ok_or_else(|| AppError::BadRequest("LemonSqueezy not configured".into()))?;

            let variant_id = query.variant_id.as_ref()
                .ok_or_else(|| AppError::BadRequest("variant_id required for LemonSqueezy".into()))?;

            let client = LemonSqueezyClient::new(&config);
            let (_, url) = client
                .create_checkout(
                    &session.id,
                    &query.project_id,
                    &query.product_id,
                    variant_id,
                    &callback_url,
                )
                .await?;
            url
        }
    };

    Ok(Redirect::temporary(&checkout_url))
}
