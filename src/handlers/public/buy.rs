use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::Json;
use crate::models::CreatePaymentSession;
use crate::payments::{LemonSqueezyClient, PaymentProvider, StripeClient};

/// Simplified BuyRequest - Paycheck knows the product pricing details.
/// Device info is NOT required here - purchase ≠ activation.
/// Redirect URL is configured per-project, not per-request.
#[derive(Debug, Deserialize)]
pub struct BuyRequest {
    /// Public key - identifies the project (preferred over product_id lookup)
    #[serde(default)]
    pub public_key: Option<String>,
    /// Product ID - Paycheck looks up project and pricing from this
    pub product_id: String,
    /// Optional: explicit payment provider (auto-detected if not specified)
    #[serde(default)]
    pub provider: Option<String>,
    /// Optional: developer-managed customer identifier (flows through to license)
    #[serde(default)]
    pub customer_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BuyResponse {
    pub checkout_url: String,
    pub session_id: String,
}

pub async fn initiate_buy(
    State(state): State<AppState>,
    Json(request): Json<BuyRequest>,
) -> Result<Json<BuyResponse>> {
    let conn = state.db.get()?;

    // Get product - this gives us project_id and payment config
    let product = queries::get_product_by_id(&conn, &request.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    // Get project - prefer public_key lookup if provided, otherwise use product's project_id
    let project = if let Some(ref public_key) = request.public_key {
        let project = queries::get_project_by_public_key(&conn, public_key)?
            .ok_or_else(|| AppError::NotFound("Project not found".into()))?;
        // Verify the product belongs to this project
        if product.project_id != project.id {
            return Err(AppError::BadRequest(
                "Product does not belong to this project".into(),
            ));
        }
        project
    } else {
        queries::get_project_by_id(&conn, &product.project_id)?
            .ok_or_else(|| AppError::NotFound("Project not found".into()))?
    };

    // Get organization (payment config is at org level)
    let org = queries::get_organization_by_id(&conn, &project.org_id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Determine payment provider
    let provider = if let Some(ref p) = request.provider {
        // Explicit provider specified
        p.parse::<PaymentProvider>()
            .ok()
            .ok_or_else(|| AppError::BadRequest("Invalid provider".into()))?
    } else if let Some(ref provider) = org.payment_provider {
        // Use organization's payment provider
        provider.parse::<PaymentProvider>().ok().ok_or_else(|| {
            AppError::BadRequest("Invalid payment_provider in organization".into())
        })?
    } else {
        // Auto-detect: use the only configured provider, or error if both/neither
        let has_stripe = org.has_stripe_config();
        let has_ls = org.has_ls_config();
        match (has_stripe, has_ls) {
            (true, false) => PaymentProvider::Stripe,
            (false, true) => PaymentProvider::LemonSqueezy,
            (true, true) => {
                return Err(AppError::BadRequest(
                    "Multiple payment providers configured. Specify 'provider' parameter (stripe or lemonsqueezy).".into()
                ));
            }
            (false, false) => {
                return Err(AppError::BadRequest(
                    "No payment provider configured".into(),
                ));
            }
        }
    };

    // Get payment config for this product and provider
    let provider_str = match provider {
        PaymentProvider::Stripe => "stripe",
        PaymentProvider::LemonSqueezy => "lemonsqueezy",
    };
    let payment_config = queries::get_payment_config(&conn, &product.id, provider_str)?
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "No payment config for provider '{}' on this product",
                provider_str
            ))
        })?;

    // Create payment session (NO device info - that comes at activation time)
    let session = queries::create_payment_session(
        &conn,
        &CreatePaymentSession {
            product_id: request.product_id.clone(),
            customer_id: request.customer_id.clone(),
        },
    )?;

    // Build callback URL (the payment provider will redirect here after success)
    let callback_url = format!("{}/callback?session={}", state.base_url, session.id);
    let cancel_url = format!("{}/cancel", state.base_url);

    // Create checkout with the appropriate provider, using payment config
    let checkout_url = match provider {
        PaymentProvider::Stripe => {
            let config = org
                .decrypt_stripe_config(&state.master_key)?
                .ok_or_else(|| AppError::BadRequest("Stripe not configured".into()))?;

            // Get price from payment config
            let price_cents = payment_config.price_cents.ok_or_else(|| {
                AppError::BadRequest("Payment config has no price_cents configured.".into())
            })? as u64;
            let currency = payment_config.currency.as_deref().unwrap_or("usd");

            let client = StripeClient::new(&config);
            let (_, url) = client
                .create_checkout_session(
                    &session.id,
                    &product.project_id,
                    &product.id,
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
            let config = org
                .decrypt_ls_config(&state.master_key)?
                .ok_or_else(|| AppError::BadRequest("LemonSqueezy not configured".into()))?;

            // Get variant ID from payment config
            let variant_id = payment_config.ls_variant_id.as_ref().ok_or_else(|| {
                AppError::BadRequest("Payment config has no ls_variant_id configured.".into())
            })?;

            let client = LemonSqueezyClient::new(&config);
            let (_, url) = client
                .create_checkout(
                    &session.id,
                    &product.project_id,
                    &product.id,
                    variant_id,
                    &callback_url,
                )
                .await?;
            url
        }
    };

    Ok(Json(BuyResponse {
        checkout_url,
        session_id: session.id,
    }))
}
