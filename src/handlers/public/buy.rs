use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::Json;
use crate::models::CreatePaymentSession;
use crate::payments::{LemonSqueezyClient, PaymentProvider, StripeClient};

/// Simplified BuyRequest - Paycheck knows the product pricing details.
/// Device info is NOT required here - purchase ≠ activation.
#[derive(Debug, Deserialize)]
pub struct BuyRequest {
    /// Product ID - Paycheck looks up project and pricing from this
    pub product_id: String,
    /// Optional: explicit payment provider (auto-detected if not specified)
    #[serde(default)]
    pub provider: Option<String>,
    /// Optional: developer-managed customer identifier (flows through to license)
    #[serde(default)]
    pub customer_id: Option<String>,
    /// Optional: redirect URL after payment (must be in project's allowed_redirect_urls)
    #[serde(default)]
    pub redirect: Option<String>,
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

    // Get project from product
    let project = queries::get_project_by_id(&conn, &product.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    // Validate redirect URL against project's allowlist
    let validated_redirect = if let Some(ref redirect) = request.redirect {
        if project.allowed_redirect_urls.is_empty() {
            return Err(AppError::BadRequest(
                "Redirect URL provided but project has no allowed redirect URLs configured".into(),
            ));
        }
        if !project.allowed_redirect_urls.contains(redirect) {
            return Err(AppError::BadRequest(
                "Redirect URL is not in project's allowed redirect URLs".into(),
            ));
        }
        Some(redirect.clone())
    } else {
        None
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
    } else if let Some(ref default) = org.default_provider {
        // Use organization's default provider
        default.parse::<PaymentProvider>().ok().ok_or_else(|| {
            AppError::BadRequest("Invalid default_provider in organization".into())
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

    // Create payment session (NO device info - that comes at activation time)
    let session = queries::create_payment_session(
        &conn,
        &CreatePaymentSession {
            product_id: request.product_id.clone(),
            customer_id: request.customer_id.clone(),
            redirect_url: validated_redirect,
        },
    )?;

    // Build callback URL (the payment provider will redirect here after success)
    let callback_url = format!("{}/callback?session={}", state.base_url, session.id);
    let cancel_url = format!("{}/cancel", state.base_url);

    // Create checkout with the appropriate provider, using product config
    let checkout_url = match provider {
        PaymentProvider::Stripe => {
            let config = org
                .decrypt_stripe_config(&state.master_key)?
                .ok_or_else(|| AppError::BadRequest("Stripe not configured".into()))?;

            // Get price from product config
            let price_cents = product.price_cents.ok_or_else(|| {
                AppError::BadRequest(
                    "Product has no price_cents configured. Set it in the product settings.".into(),
                )
            })? as u64;
            let currency = product.currency.as_deref().unwrap_or("usd");

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

            // Get variant ID from product config
            let variant_id = product.ls_variant_id.as_ref().ok_or_else(|| {
                AppError::BadRequest(
                    "Product has no ls_variant_id configured. Set it in the product settings."
                        .into(),
                )
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
