use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::db::{queries, AppState};
use crate::payments::{StripeCheckoutSession, StripeClient, StripeInvoice, StripeSubscription, StripeWebhookEvent};

pub async fn handle_stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let signature = match headers.get("stripe-signature") {
        Some(sig) => match sig.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return (StatusCode::BAD_REQUEST, "Invalid signature header"),
        },
        None => return (StatusCode::BAD_REQUEST, "Missing stripe-signature header"),
    };

    // Parse the event
    let event: StripeWebhookEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to parse Stripe webhook: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid JSON");
        }
    };

    // Route to appropriate handler based on event type
    match event.event_type.as_str() {
        "checkout.session.completed" => {
            handle_checkout_completed(state, &body, &signature, &event).await
        }
        "invoice.paid" => {
            handle_invoice_paid(state, &body, &signature, &event).await
        }
        "customer.subscription.deleted" => {
            handle_subscription_deleted(state, &body, &signature, &event).await
        }
        _ => (StatusCode::OK, "Event ignored"),
    }
}

/// Handle initial checkout completion - creates license
async fn handle_checkout_completed(
    state: AppState,
    body: &Bytes,
    signature: &str,
    event: &StripeWebhookEvent,
) -> (StatusCode, &'static str) {
    // Parse checkout session from event data
    let session: StripeCheckoutSession = match serde_json::from_value(event.data.object.clone()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to parse checkout session: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid checkout session");
        }
    };

    // Extract metadata
    let paycheck_session_id = match &session.metadata.paycheck_session_id {
        Some(id) => id,
        None => return (StatusCode::OK, "No paycheck session ID"),
    };
    let project_id = match &session.metadata.project_id {
        Some(id) => id,
        None => return (StatusCode::OK, "No project ID"),
    };

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB connection error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    let project = match queries::get_project_by_id(&conn, project_id) {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::OK, "Project not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Verify webhook signature
    let stripe_config = match &project.stripe_config {
        Some(c) => c,
        None => return (StatusCode::OK, "Stripe not configured"),
    };

    let client = StripeClient::new(stripe_config);
    match client.verify_webhook_signature(body, signature) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::UNAUTHORIZED, "Invalid signature"),
        Err(e) => {
            tracing::error!("Signature verification error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Signature verification failed");
        }
    }

    // Check payment status
    if session.payment_status != "paid" {
        return (StatusCode::OK, "Payment not completed");
    }

    // Get payment session
    let payment_session = match queries::get_payment_session(&conn, paycheck_session_id) {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::OK, "Payment session not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    if payment_session.completed {
        return (StatusCode::OK, "Already processed");
    }

    // Get product to compute expirations
    let product = match queries::get_product_by_id(&conn, &payment_session.product_id) {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::OK, "Product not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Compute expirations from product settings
    let now = chrono::Utc::now().timestamp();
    let expires_at = product.license_exp_days.map(|days| now + (days as i64) * 86400);
    let updates_expires_at = product.updates_exp_days.map(|days| now + (days as i64) * 86400);

    // Create license key with project's prefix (include subscription ID if present)
    let license = match queries::create_license_key(
        &conn,
        &payment_session.product_id,
        &project.license_key_prefix,
        &crate::models::CreateLicenseKey {
            email: session.customer_email.clone(),
            expires_at,
            updates_expires_at,
            payment_provider: Some("stripe".to_string()),
            payment_provider_customer_id: session.customer.clone(),
            payment_provider_subscription_id: session.subscription.clone(),
        },
    ) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to create license: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create license");
        }
    };

    // Create device
    let jti = uuid::Uuid::new_v4().to_string();
    if let Err(e) = queries::create_device(
        &conn,
        &license.id,
        &payment_session.device_id,
        payment_session.device_type,
        &jti,
        None,
    ) {
        tracing::error!("Failed to create device: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create device");
    }

    // Increment activation count
    if let Err(e) = queries::increment_activation_count(&conn, &license.id) {
        tracing::error!("Failed to increment activation count: {}", e);
    }

    // Mark session as completed
    if let Err(e) = queries::mark_payment_session_completed(&conn, paycheck_session_id) {
        tracing::error!("Failed to mark session completed: {}", e);
    }

    tracing::info!(
        "Stripe checkout completed: session={}, license={}, subscription={:?}",
        paycheck_session_id,
        license.key,
        session.subscription
    );

    (StatusCode::OK, "OK")
}

/// Handle subscription renewal - extends license expiration
async fn handle_invoice_paid(
    state: AppState,
    body: &Bytes,
    signature: &str,
    event: &StripeWebhookEvent,
) -> (StatusCode, &'static str) {
    // Parse invoice from event data
    let invoice: StripeInvoice = match serde_json::from_value(event.data.object.clone()) {
        Ok(i) => i,
        Err(e) => {
            tracing::error!("Failed to parse invoice: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid invoice");
        }
    };

    // Only process subscription renewals (not initial creation)
    match invoice.billing_reason.as_deref() {
        Some("subscription_cycle") | Some("subscription_update") => {}
        Some("subscription_create") => {
            // Initial subscription is handled by checkout.session.completed
            return (StatusCode::OK, "Initial subscription - handled by checkout");
        }
        _ => return (StatusCode::OK, "Not a subscription renewal"),
    }

    let subscription_id = match &invoice.subscription {
        Some(id) => id,
        None => return (StatusCode::OK, "No subscription ID"),
    };

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB connection error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Find license by subscription ID
    let license = match queries::get_license_key_by_subscription(&conn, "stripe", subscription_id) {
        Ok(Some(l)) => l,
        Ok(None) => {
            tracing::warn!("No license found for Stripe subscription: {}", subscription_id);
            return (StatusCode::OK, "License not found for subscription");
        }
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Get project to verify signature
    let product = match queries::get_product_by_id(&conn, &license.product_id) {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::OK, "Product not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    let project = match queries::get_project_by_id(&conn, &product.project_id) {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::OK, "Project not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Verify webhook signature
    let stripe_config = match &project.stripe_config {
        Some(c) => c,
        None => return (StatusCode::OK, "Stripe not configured"),
    };

    let client = StripeClient::new(stripe_config);
    match client.verify_webhook_signature(body, signature) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::UNAUTHORIZED, "Invalid signature"),
        Err(e) => {
            tracing::error!("Signature verification error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Signature verification failed");
        }
    }

    // Check invoice status
    if invoice.status != "paid" {
        return (StatusCode::OK, "Invoice not paid");
    }

    // Extend license expiration based on product settings
    let now = chrono::Utc::now().timestamp();
    let new_expires_at = product.license_exp_days.map(|days| now + (days as i64) * 86400);
    let new_updates_expires_at = product.updates_exp_days.map(|days| now + (days as i64) * 86400);

    if let Err(e) = queries::extend_license_expiration(&conn, &license.id, new_expires_at, new_updates_expires_at) {
        tracing::error!("Failed to extend license: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to extend license");
    }

    tracing::info!(
        "Stripe subscription renewed: subscription={}, license={}, new_expires_at={:?}",
        subscription_id,
        license.key,
        new_expires_at
    );

    (StatusCode::OK, "OK")
}

/// Handle subscription cancellation - license will expire naturally
/// We don't revoke immediately because the customer paid for the current period
async fn handle_subscription_deleted(
    state: AppState,
    body: &Bytes,
    signature: &str,
    event: &StripeWebhookEvent,
) -> (StatusCode, &'static str) {
    // Parse subscription from event data
    let subscription: StripeSubscription = match serde_json::from_value(event.data.object.clone()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to parse subscription: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid subscription");
        }
    };

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB connection error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Find license by subscription ID
    let license = match queries::get_license_key_by_subscription(&conn, "stripe", &subscription.id) {
        Ok(Some(l)) => l,
        Ok(None) => {
            tracing::warn!("No license found for Stripe subscription: {}", subscription.id);
            return (StatusCode::OK, "License not found for subscription");
        }
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Get project to verify signature
    let product = match queries::get_product_by_id(&conn, &license.product_id) {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::OK, "Product not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    let project = match queries::get_project_by_id(&conn, &product.project_id) {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::OK, "Project not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Verify webhook signature
    let stripe_config = match &project.stripe_config {
        Some(c) => c,
        None => return (StatusCode::OK, "Stripe not configured"),
    };

    let client = StripeClient::new(stripe_config);
    match client.verify_webhook_signature(body, signature) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::UNAUTHORIZED, "Invalid signature"),
        Err(e) => {
            tracing::error!("Signature verification error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Signature verification failed");
        }
    }

    // Don't revoke - let the license expire naturally at expires_at
    // The customer paid for the current period and should keep access
    tracing::info!(
        "Stripe subscription cancelled: subscription={}, license={}, expires_at={:?} (will expire naturally)",
        subscription.id,
        license.key,
        license.expires_at
    );

    (StatusCode::OK, "OK")
}
