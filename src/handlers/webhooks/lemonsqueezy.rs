use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::crypto::MasterKey;
use crate::db::AppState;
use crate::models::Organization;
use crate::payments::{
    LemonSqueezyClient, LemonSqueezyOrderAttributes, LemonSqueezySubscriptionInvoiceAttributes,
    LemonSqueezyWebhookEvent,
};

use super::common::{
    CancellationData, CheckoutData, RenewalData, WebhookEvent, WebhookProvider, WebhookResult,
    handle_webhook,
};

/// LemonSqueezy webhook provider implementation.
pub struct LemonSqueezyWebhookProvider;

impl WebhookProvider for LemonSqueezyWebhookProvider {
    fn provider_name(&self) -> &'static str {
        "lemonsqueezy"
    }

    fn extract_signature(&self, headers: &HeaderMap) -> Result<String, WebhookResult> {
        headers
            .get("x-signature")
            .ok_or((StatusCode::BAD_REQUEST, "Missing x-signature header"))?
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature header"))
    }

    fn verify_signature(
        &self,
        org: &Organization,
        master_key: &MasterKey,
        body: &Bytes,
        signature: &str,
    ) -> Result<bool, WebhookResult> {
        let ls_config = org
            .decrypt_ls_config(master_key)
            .map_err(|e| {
                tracing::error!("Failed to decrypt LemonSqueezy config: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Config decryption failed",
                )
            })?
            .ok_or((StatusCode::OK, "LemonSqueezy not configured"))?;

        let client = LemonSqueezyClient::new(&ls_config);
        client
            .verify_webhook_signature(body, signature)
            .map_err(|e| {
                tracing::error!("Signature verification error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Signature verification failed",
                )
            })
    }

    fn parse_event(&self, body: &Bytes) -> Result<WebhookEvent, WebhookResult> {
        let event: LemonSqueezyWebhookEvent = serde_json::from_slice(body).map_err(|e| {
            tracing::error!("Failed to parse LemonSqueezy webhook: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid JSON")
        })?;

        match event.meta.event_name.as_str() {
            "order_created" => parse_order_created(&event),
            "subscription_payment_success" => parse_subscription_payment(&event),
            "subscription_cancelled" => parse_subscription_cancelled(&event),
            _ => Ok(WebhookEvent::Ignored),
        }
    }
}

fn parse_order_created(event: &LemonSqueezyWebhookEvent) -> Result<WebhookEvent, WebhookResult> {
    let order: LemonSqueezyOrderAttributes = serde_json::from_value(event.data.attributes.clone())
        .map_err(|e| {
            tracing::error!("Failed to parse order attributes: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid order attributes")
        })?;

    // Check order status
    if order.status != "paid" {
        return Ok(WebhookEvent::Ignored);
    }

    let custom_data = event
        .meta
        .custom_data
        .as_ref()
        .ok_or((StatusCode::OK, "No custom data"))?;

    let session_id = custom_data
        .paycheck_session_id
        .clone()
        .ok_or((StatusCode::OK, "No paycheck session ID"))?;
    let project_id = custom_data
        .project_id
        .clone()
        .ok_or((StatusCode::OK, "No project ID"))?;

    // Extract subscription ID if this is a subscription order
    let subscription_id = order
        .first_order_item
        .as_ref()
        .and_then(|item| item.subscription_id)
        .map(|id| id.to_string());

    Ok(WebhookEvent::CheckoutCompleted(CheckoutData {
        session_id,
        project_id,
        customer_id: order.customer_id.map(|id| id.to_string()),
        customer_email: order.user_email,
        subscription_id,
        order_id: Some(event.data.id.clone()),
    }))
}

fn parse_subscription_payment(
    event: &LemonSqueezyWebhookEvent,
) -> Result<WebhookEvent, WebhookResult> {
    let invoice: LemonSqueezySubscriptionInvoiceAttributes =
        serde_json::from_value(event.data.attributes.clone()).map_err(|e| {
            tracing::error!("Failed to parse subscription invoice: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid subscription invoice")
        })?;

    Ok(WebhookEvent::SubscriptionRenewed(RenewalData {
        subscription_id: invoice.subscription_id.to_string(),
        // LemonSqueezy subscription_payment_success is always a renewal
        // Initial payment comes via order_created
        is_renewal: true,
        is_paid: invoice.status == "paid",
        // Use invoice ID (data.id) as unique event identifier for replay prevention
        event_id: Some(event.data.id.clone()),
    }))
}

fn parse_subscription_cancelled(
    event: &LemonSqueezyWebhookEvent,
) -> Result<WebhookEvent, WebhookResult> {
    // For subscription events, the subscription ID is in data.id
    Ok(WebhookEvent::SubscriptionCancelled(CancellationData {
        subscription_id: event.data.id.clone(),
    }))
}

/// Axum handler for LemonSqueezy webhooks.
pub async fn handle_lemonsqueezy_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    handle_webhook(&LemonSqueezyWebhookProvider, &state, headers, body).await
}
