use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::Json;
use crate::models::{CreatePaymentSession, DeviceType};
use crate::payments::{LemonSqueezyClient, PaymentProvider, StripeClient};

#[derive(Debug, Deserialize)]
pub struct BuyRequest {
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
    /// Optional redirect URL after payment (must be in project's allowed_redirect_urls)
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

    // Validate device type
    let device_type = request
        .device_type
        .parse::<DeviceType>()
        .ok()
        .ok_or_else(|| AppError::BadRequest("Invalid device_type".into()))?;

    // Get project
    let project = queries::get_project_by_id(&conn, &request.project_id)?
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

    // Get product
    let product = queries::get_product_by_id(&conn, &request.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    // Verify product belongs to project
    if product.project_id != request.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    // Determine payment provider
    let provider = if let Some(ref p) = request.provider {
        // Explicit provider specified in query
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
                    "Multiple payment providers configured. Specify 'provider' query parameter (stripe or lemonsqueezy).".into()
                ));
            }
            (false, false) => {
                return Err(AppError::BadRequest(
                    "No payment provider configured".into(),
                ));
            }
        }
    };

    // Create payment session (customer_id flows through to license on webhook)
    let session = queries::create_payment_session(
        &conn,
        &CreatePaymentSession {
            product_id: request.product_id.clone(),
            device_id: request.device_id.clone(),
            device_type,
            customer_id: request.customer_id.clone(),
            redirect_url: validated_redirect,
        },
    )?;

    // Build callback URL (the payment provider will redirect here after success)
    let callback_url = format!("{}/callback?session={}", state.base_url, session.id);
    let cancel_url = format!("{}/cancel", state.base_url);

    // Create checkout with the appropriate provider
    let checkout_url = match provider {
        PaymentProvider::Stripe => {
            let config = org
                .decrypt_stripe_config(&state.master_key)?
                .ok_or_else(|| AppError::BadRequest("Stripe not configured".into()))?;

            let price_cents = request
                .price_cents
                .ok_or_else(|| AppError::BadRequest("price_cents required for Stripe".into()))?;
            let currency = request.currency.as_deref().unwrap_or("usd");

            let client = StripeClient::new(&config);
            let (_, url) = client
                .create_checkout_session(
                    &session.id,
                    &request.project_id,
                    &request.product_id,
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

            let variant_id = request.variant_id.as_ref().ok_or_else(|| {
                AppError::BadRequest("variant_id required for LemonSqueezy".into())
            })?;

            let client = LemonSqueezyClient::new(&config);
            let (_, url) = client
                .create_checkout(
                    &session.id,
                    &request.project_id,
                    &request.product_id,
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
