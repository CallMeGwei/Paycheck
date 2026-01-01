use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;

use crate::error::{AppError, Result};
use crate::models::StripeConfig;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize)]
struct CreateCheckoutSessionRequest<'a> {
    mode: &'a str,
    success_url: &'a str,
    cancel_url: &'a str,
    line_items: Vec<LineItem<'a>>,
    metadata: CheckoutMetadata<'a>,
}

#[derive(Debug, Serialize)]
struct LineItem<'a> {
    price_data: PriceData<'a>,
    quantity: u32,
}

#[derive(Debug, Serialize)]
struct PriceData<'a> {
    currency: &'a str,
    unit_amount: u64,
    product_data: ProductData<'a>,
}

#[derive(Debug, Serialize)]
struct ProductData<'a> {
    name: &'a str,
}

#[derive(Debug, Serialize)]
struct CheckoutMetadata<'a> {
    paycheck_session_id: &'a str,
    project_id: &'a str,
    product_id: &'a str,
}

#[derive(Debug, Deserialize)]
struct CreateCheckoutSessionResponse {
    id: String,
    url: String,
}

#[derive(Debug, Clone)]
pub struct StripeClient {
    client: Client,
    secret_key: String,
    webhook_secret: String,
}

impl StripeClient {
    pub fn new(config: &StripeConfig) -> Self {
        Self {
            client: Client::new(),
            secret_key: config.secret_key.clone(),
            webhook_secret: config.webhook_secret.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_checkout_session(
        &self,
        session_id: &str,
        project_id: &str,
        product_id: &str,
        product_name: &str,
        price_cents: u64,
        currency: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<(String, String)> {
        let request = CreateCheckoutSessionRequest {
            mode: "payment",
            success_url,
            cancel_url,
            line_items: vec![LineItem {
                price_data: PriceData {
                    currency,
                    unit_amount: price_cents,
                    product_data: ProductData { name: product_name },
                },
                quantity: 1,
            }],
            metadata: CheckoutMetadata {
                paycheck_session_id: session_id,
                project_id,
                product_id,
            },
        };

        let response = self
            .client
            .post("https://api.stripe.com/v1/checkout/sessions")
            .basic_auth(&self.secret_key, None::<&str>)
            .form(&[
                ("mode", request.mode),
                ("success_url", request.success_url),
                ("cancel_url", request.cancel_url),
                ("line_items[0][price_data][currency]", currency),
                ("line_items[0][price_data][unit_amount]", &price_cents.to_string()),
                ("line_items[0][price_data][product_data][name]", product_name),
                ("line_items[0][quantity]", "1"),
                ("metadata[paycheck_session_id]", session_id),
                ("metadata[project_id]", project_id),
                ("metadata[product_id]", product_id),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Stripe API error: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!("Stripe API error: {}", error_text)));
        }

        let session: CreateCheckoutSessionResponse = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse Stripe response: {}", e)))?;

        Ok((session.id, session.url))
    }

    /// Maximum age of a webhook timestamp before it's rejected (in seconds).
    /// Stripe recommends 300 seconds (5 minutes).
    const WEBHOOK_TIMESTAMP_TOLERANCE_SECS: i64 = 300;

    pub fn verify_webhook_signature(&self, payload: &[u8], signature: &str) -> Result<bool> {
        // Stripe signature format: t=timestamp,v1=signature
        let parts: Vec<&str> = signature.split(',').collect();

        let mut timestamp = None;
        let mut sig_v1 = None;

        for part in parts {
            if let Some(t) = part.strip_prefix("t=") {
                timestamp = Some(t);
            } else if let Some(s) = part.strip_prefix("v1=") {
                sig_v1 = Some(s);
            }
        }

        let timestamp_str = timestamp.ok_or_else(|| AppError::BadRequest("Invalid signature format".into()))?;
        let sig_v1 = sig_v1.ok_or_else(|| AppError::BadRequest("Invalid signature format".into()))?;

        // Parse and validate timestamp to prevent replay attacks.
        // Reject webhooks older than WEBHOOK_TIMESTAMP_TOLERANCE_SECS.
        let timestamp: i64 = timestamp_str
            .parse()
            .map_err(|_| AppError::BadRequest("Invalid timestamp in signature".into()))?;

        let now = chrono::Utc::now().timestamp();
        let age = now - timestamp;

        if age > Self::WEBHOOK_TIMESTAMP_TOLERANCE_SECS {
            tracing::warn!(
                "Stripe webhook rejected: timestamp too old (age={}s, max={}s)",
                age,
                Self::WEBHOOK_TIMESTAMP_TOLERANCE_SECS
            );
            return Ok(false);
        }

        // Also reject timestamps from the future (clock skew tolerance: 60 seconds)
        if age < -60 {
            tracing::warn!("Stripe webhook rejected: timestamp in the future (age={}s)", age);
            return Ok(false);
        }

        // Construct signed payload
        let signed_payload = format!("{}.{}", timestamp_str, String::from_utf8_lossy(payload));

        // Compute expected signature
        let mut mac = HmacSha256::new_from_slice(self.webhook_secret.as_bytes())
            .map_err(|_| AppError::Internal("Invalid webhook secret".into()))?;
        mac.update(signed_payload.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        // Use constant-time comparison to prevent timing attacks.
        // An attacker could otherwise measure response times to progressively
        // discover the correct signature byte-by-byte.
        let expected_bytes = expected.as_bytes();
        let provided_bytes = sig_v1.as_bytes();

        // Length check is not constant-time, but that's fine - signature length
        // is not secret (it's always 64 hex chars for SHA-256)
        if expected_bytes.len() != provided_bytes.len() {
            return Ok(false);
        }

        Ok(expected_bytes.ct_eq(provided_bytes).into())
    }
}

/// Generic Stripe webhook event - object is parsed based on event_type
#[derive(Debug, Deserialize)]
pub struct StripeWebhookEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: StripeEventData,
}

#[derive(Debug, Deserialize)]
pub struct StripeEventData {
    pub object: serde_json::Value,
}

// ============ checkout.session.completed ============

#[derive(Debug, Deserialize)]
pub struct StripeCheckoutSession {
    pub id: String,
    pub mode: Option<String>, // "payment" or "subscription"
    pub payment_status: String,
    pub customer: Option<String>,
    pub customer_email: Option<String>,
    pub subscription: Option<String>, // Present for subscription mode
    pub metadata: StripeMetadata,
}

#[derive(Debug, Deserialize)]
pub struct StripeMetadata {
    pub paycheck_session_id: Option<String>,
    pub project_id: Option<String>,
    pub product_id: Option<String>,
}

// ============ invoice.paid ============

#[derive(Debug, Deserialize)]
pub struct StripeInvoice {
    pub id: String,
    pub customer: Option<String>,
    pub subscription: Option<String>,
    pub billing_reason: Option<String>, // "subscription_create", "subscription_cycle", etc.
    pub status: String, // "paid", "open", etc.
}

// ============ customer.subscription.deleted ============

#[derive(Debug, Deserialize)]
pub struct StripeSubscription {
    pub id: String,
    pub customer: Option<String>,
    pub status: String, // "active", "canceled", etc.
}
