use axum::{extract::State, response::Redirect};
use serde::Deserialize;

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::Query;
use crate::models::{CreatePaymentSession, DeviceType};
use crate::payments::{LemonSqueezyClient, PaymentProvider, StripeClient};

#[derive(Debug, Deserialize)]
pub struct BuyQuery {
    pub project_id: String,
    pub product_id: String,
    pub device_id: String,
    pub device_type: String,
    /// Developer-managed customer identifier (flows through to license)
    #[serde(default)]
    pub customer_id: Option<String>,
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
    State(state): State<AppState>,
    Query(query): Query<BuyQuery>,
) -> Result<Redirect> {
    let conn = state.db.get()?;

    // Validate device type
    let device_type = query.device_type.parse::<DeviceType>()
        .ok().ok_or_else(|| AppError::BadRequest("Invalid device_type".into()))?;

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
        // Explicit provider specified in query
        p.parse::<PaymentProvider>()
            .ok().ok_or_else(|| AppError::BadRequest("Invalid provider".into()))?
    } else if let Some(ref default) = project.default_provider {
        // Use project's default provider
        default.parse::<PaymentProvider>()
            .ok().ok_or_else(|| AppError::BadRequest("Invalid default_provider in project".into()))?
    } else {
        // Auto-detect: use the only configured provider, or error if both/neither
        let has_stripe = project.has_stripe_config();
        let has_ls = project.has_ls_config();
        match (has_stripe, has_ls) {
            (true, false) => PaymentProvider::Stripe,
            (false, true) => PaymentProvider::LemonSqueezy,
            (true, true) => {
                return Err(AppError::BadRequest(
                    "Multiple payment providers configured. Specify 'provider' query parameter (stripe or lemonsqueezy).".into()
                ));
            }
            (false, false) => {
                return Err(AppError::BadRequest("No payment provider configured".into()));
            }
        }
    };

    // Create payment session (customer_id flows through to license on webhook)
    let session = queries::create_payment_session(
        &conn,
        &CreatePaymentSession {
            product_id: query.product_id.clone(),
            device_id: query.device_id.clone(),
            device_type,
            customer_id: query.customer_id.clone(),
        },
    )?;

    // Build callback URL (the payment provider will redirect here after success)
    let callback_url = format!("{}/callback?session={}", state.base_url, session.id);
    let cancel_url = format!("{}/cancel", state.base_url);

    // Create checkout with the appropriate provider
    let checkout_url = match provider {
        PaymentProvider::Stripe => {
            let config = project.decrypt_stripe_config(&state.master_key)?
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
            let config = project.decrypt_ls_config(&state.master_key)?
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
