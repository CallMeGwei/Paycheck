use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::db::{queries, AppState};
use crate::payments::{
    LemonSqueezyClient, LemonSqueezyOrderAttributes, LemonSqueezySubscriptionAttributes,
    LemonSqueezySubscriptionInvoiceAttributes, LemonSqueezyWebhookEvent,
};

pub async fn handle_lemonsqueezy_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let signature = match headers.get("x-signature") {
        Some(sig) => match sig.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return (StatusCode::BAD_REQUEST, "Invalid signature header"),
        },
        None => return (StatusCode::BAD_REQUEST, "Missing x-signature header"),
    };

    // Parse the event
    let event: LemonSqueezyWebhookEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to parse LemonSqueezy webhook: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid JSON");
        }
    };

    // Route to appropriate handler based on event type
    match event.meta.event_name.as_str() {
        "order_created" => handle_order_created(state, &body, &signature, &event).await,
        "subscription_payment_success" => {
            handle_subscription_payment(state, &body, &signature, &event).await
        }
        "subscription_cancelled" => {
            handle_subscription_cancelled(state, &body, &signature, &event).await
        }
        _ => (StatusCode::OK, "Event ignored"),
    }
}

/// Handle initial order - creates license
async fn handle_order_created(
    state: AppState,
    body: &Bytes,
    signature: &str,
    event: &LemonSqueezyWebhookEvent,
) -> (StatusCode, &'static str) {
    // Parse order attributes from event data
    let order: LemonSqueezyOrderAttributes = match serde_json::from_value(event.data.attributes.clone()) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("Failed to parse order attributes: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid order attributes");
        }
    };

    // Extract custom data
    let custom_data = match &event.meta.custom_data {
        Some(data) => data,
        None => return (StatusCode::OK, "No custom data"),
    };

    let session_id = match &custom_data.paycheck_session_id {
        Some(id) => id,
        None => return (StatusCode::OK, "No paycheck session ID"),
    };
    let project_id = match &custom_data.project_id {
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
    let ls_config = match &project.ls_config {
        Some(c) => c,
        None => return (StatusCode::OK, "LemonSqueezy not configured"),
    };

    let client = LemonSqueezyClient::new(ls_config);
    match client.verify_webhook_signature(body, signature) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::UNAUTHORIZED, "Invalid signature"),
        Err(e) => {
            tracing::error!("Signature verification error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Signature verification failed");
        }
    }

    // Check order status
    if order.status != "paid" {
        return (StatusCode::OK, "Order not paid");
    }

    // Get payment session
    let payment_session = match queries::get_payment_session(&conn, session_id) {
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

    // Extract subscription ID if this is a subscription order
    let subscription_id = order
        .first_order_item
        .as_ref()
        .and_then(|item| item.subscription_id)
        .map(|id| id.to_string());

    // Create license key with project's prefix
    // customer_id flows through from payment session (set in /buy URL)
    let license = match queries::create_license_key(
        &conn,
        &payment_session.product_id,
        &project.license_key_prefix,
        &crate::models::CreateLicenseKey {
            customer_id: payment_session.customer_id.clone(),
            expires_at,
            updates_expires_at,
            payment_provider: Some("lemonsqueezy".to_string()),
            payment_provider_customer_id: order.customer_id.map(|id| id.to_string()),
            payment_provider_subscription_id: subscription_id.clone(),
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
    if let Err(e) = queries::mark_payment_session_completed(&conn, session_id) {
        tracing::error!("Failed to mark session completed: {}", e);
    }

    tracing::info!(
        "LemonSqueezy order completed: session={}, license={}, subscription={:?}",
        session_id,
        license.key,
        subscription_id
    );

    (StatusCode::OK, "OK")
}

/// Handle subscription renewal - extends license expiration
async fn handle_subscription_payment(
    state: AppState,
    body: &Bytes,
    signature: &str,
    event: &LemonSqueezyWebhookEvent,
) -> (StatusCode, &'static str) {
    // Parse subscription invoice attributes from event data
    let invoice: LemonSqueezySubscriptionInvoiceAttributes =
        match serde_json::from_value(event.data.attributes.clone()) {
            Ok(i) => i,
            Err(e) => {
                tracing::error!("Failed to parse subscription invoice: {}", e);
                return (StatusCode::BAD_REQUEST, "Invalid subscription invoice");
            }
        };

    let subscription_id = invoice.subscription_id.to_string();

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB connection error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Find license by subscription ID
    let license = match queries::get_license_key_by_subscription(&conn, "lemonsqueezy", &subscription_id) {
        Ok(Some(l)) => l,
        Ok(None) => {
            tracing::warn!("No license found for LemonSqueezy subscription: {}", subscription_id);
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
    let ls_config = match &project.ls_config {
        Some(c) => c,
        None => return (StatusCode::OK, "LemonSqueezy not configured"),
    };

    let client = LemonSqueezyClient::new(ls_config);
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
        "LemonSqueezy subscription renewed: subscription={}, license={}, new_expires_at={:?}",
        subscription_id,
        license.key,
        new_expires_at
    );

    (StatusCode::OK, "OK")
}

/// Handle subscription cancellation - license will expire naturally
/// We don't revoke immediately because the customer paid for the current period
async fn handle_subscription_cancelled(
    state: AppState,
    body: &Bytes,
    signature: &str,
    event: &LemonSqueezyWebhookEvent,
) -> (StatusCode, &'static str) {
    // Parse subscription attributes from event data
    let subscription: LemonSqueezySubscriptionAttributes =
        match serde_json::from_value(event.data.attributes.clone()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to parse subscription: {}", e);
                return (StatusCode::BAD_REQUEST, "Invalid subscription");
            }
        };

    // The subscription ID is in the data.id field for subscription events
    let subscription_id = &event.data.id;

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB connection error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Find license by subscription ID
    let license = match queries::get_license_key_by_subscription(&conn, "lemonsqueezy", subscription_id) {
        Ok(Some(l)) => l,
        Ok(None) => {
            tracing::warn!("No license found for LemonSqueezy subscription: {}", subscription_id);
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
    let ls_config = match &project.ls_config {
        Some(c) => c,
        None => return (StatusCode::OK, "LemonSqueezy not configured"),
    };

    let client = LemonSqueezyClient::new(ls_config);
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
        "LemonSqueezy subscription cancelled: subscription={}, license={}, expires_at={:?}, status={} (will expire naturally)",
        subscription_id,
        license.key,
        license.expires_at,
        subscription.status
    );

    (StatusCode::OK, "OK")
}
