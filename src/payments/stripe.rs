use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

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

        let timestamp = timestamp.ok_or_else(|| AppError::BadRequest("Invalid signature format".into()))?;
        let sig_v1 = sig_v1.ok_or_else(|| AppError::BadRequest("Invalid signature format".into()))?;

        // Construct signed payload
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));

        // Compute expected signature
        let mut mac = HmacSha256::new_from_slice(self.webhook_secret.as_bytes())
            .map_err(|_| AppError::Internal("Invalid webhook secret".into()))?;
        mac.update(signed_payload.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        Ok(expected == sig_v1)
    }
}

#[derive(Debug, Deserialize)]
pub struct StripeWebhookEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: StripeEventData,
}

#[derive(Debug, Deserialize)]
pub struct StripeEventData {
    pub object: StripeCheckoutSession,
}

#[derive(Debug, Deserialize)]
pub struct StripeCheckoutSession {
    pub id: String,
    pub payment_status: String,
    pub customer_email: Option<String>,
    pub metadata: StripeMetadata,
}

#[derive(Debug, Deserialize)]
pub struct StripeMetadata {
    pub paycheck_session_id: Option<String>,
    pub project_id: Option<String>,
    pub product_id: Option<String>,
}
