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
    StripeCheckoutSession, StripeClient, StripeInvoice, StripeSubscription, StripeWebhookEvent,
};

use super::common::{
    CancellationData, CheckoutData, RenewalData, WebhookEvent, WebhookProvider, WebhookResult,
    handle_webhook,
};

/// Stripe webhook provider implementation.
pub struct StripeWebhookProvider;

impl WebhookProvider for StripeWebhookProvider {
    fn provider_name(&self) -> &'static str {
        "stripe"
    }

    fn extract_signature(&self, headers: &HeaderMap) -> Result<String, WebhookResult> {
        headers
            .get("stripe-signature")
            .ok_or((StatusCode::BAD_REQUEST, "Missing stripe-signature header"))?
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
        // Handle both missing and corrupted configs gracefully by returning 200 OK.
        // This prevents payment providers from retrying indefinitely on 5xx errors
        // and avoids leaking internal state about config status.
        let stripe_config = match org.decrypt_stripe_config(master_key) {
            Ok(Some(config)) => config,
            Ok(None) => return Err((StatusCode::OK, "Stripe not configured")),
            Err(e) => {
                tracing::error!("Failed to decrypt Stripe config for org {}: {}", org.id, e);
                // Return OK to prevent retry storms - treat corrupted config as unusable
                return Err((StatusCode::OK, "Stripe config unavailable"));
            }
        };

        let client = StripeClient::new(&stripe_config);
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
        let event: StripeWebhookEvent = serde_json::from_slice(body).map_err(|e| {
            tracing::error!("Failed to parse Stripe webhook: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid JSON")
        })?;

        match event.event_type.as_str() {
            "checkout.session.completed" => parse_checkout_completed(&event),
            "invoice.paid" => parse_invoice_paid(&event),
            "customer.subscription.deleted" => parse_subscription_deleted(&event),
            _ => Ok(WebhookEvent::Ignored),
        }
    }
}

fn parse_checkout_completed(event: &StripeWebhookEvent) -> Result<WebhookEvent, WebhookResult> {
    let session: StripeCheckoutSession = serde_json::from_value(event.data.object.clone())
        .map_err(|e| {
            tracing::error!("Failed to parse checkout session: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid checkout session")
        })?;

    // Check payment status
    if session.payment_status != "paid" {
        return Ok(WebhookEvent::Ignored);
    }

    let session_id = session
        .metadata
        .paycheck_session_id
        .ok_or((StatusCode::OK, "No paycheck session ID"))?;
    let project_id = session
        .metadata
        .project_id
        .ok_or((StatusCode::OK, "No project ID"))?;

    Ok(WebhookEvent::CheckoutCompleted(CheckoutData {
        session_id,
        project_id,
        customer_id: session.customer,
        customer_email: session.customer_email,
        subscription_id: session.subscription,
        order_id: Some(session.id),
    }))
}

fn parse_invoice_paid(event: &StripeWebhookEvent) -> Result<WebhookEvent, WebhookResult> {
    let invoice: StripeInvoice =
        serde_json::from_value(event.data.object.clone()).map_err(|e| {
            tracing::error!("Failed to parse invoice: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid invoice")
        })?;

    let subscription_id = match invoice.subscription {
        Some(id) => id,
        None => return Ok(WebhookEvent::Ignored),
    };

    // Determine if this is a renewal
    let is_renewal = match invoice.billing_reason.as_deref() {
        Some("subscription_cycle") | Some("subscription_update") => true,
        Some("subscription_create") => false,
        _ => return Ok(WebhookEvent::Ignored),
    };

    Ok(WebhookEvent::SubscriptionRenewed(RenewalData {
        subscription_id,
        is_renewal,
        is_paid: invoice.status == "paid",
        // Use invoice ID as unique event identifier for replay prevention
        event_id: Some(invoice.id),
    }))
}

fn parse_subscription_deleted(event: &StripeWebhookEvent) -> Result<WebhookEvent, WebhookResult> {
    let subscription: StripeSubscription = serde_json::from_value(event.data.object.clone())
        .map_err(|e| {
            tracing::error!("Failed to parse subscription: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid subscription")
        })?;

    Ok(WebhookEvent::SubscriptionCancelled(CancellationData {
        subscription_id: subscription.id,
    }))
}

/// Axum handler for Stripe webhooks.
pub async fn handle_stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    handle_webhook(&StripeWebhookProvider, &state, headers, body).await
}
