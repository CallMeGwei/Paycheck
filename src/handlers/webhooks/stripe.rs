use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::db::{queries, DbPool};
use crate::models::DeviceType;
use crate::payments::{StripeClient, StripeWebhookEvent};

pub async fn handle_stripe_webhook(
    State(pool): State<DbPool>,
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

    // Parse the event first to get project info
    let event: StripeWebhookEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to parse Stripe webhook: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid JSON");
        }
    };

    // Only handle checkout.session.completed
    if event.event_type != "checkout.session.completed" {
        return (StatusCode::OK, "Event ignored");
    }

    // Extract metadata
    let metadata = &event.data.object.metadata;
    let session_id = match &metadata.paycheck_session_id {
        Some(id) => id,
        None => return (StatusCode::OK, "No paycheck session ID"),
    };
    let project_id = match &metadata.project_id {
        Some(id) => id,
        None => return (StatusCode::OK, "No project ID"),
    };

    // Get project to verify signature
    let conn = match pool.get() {
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
    match client.verify_webhook_signature(&body, &signature) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::UNAUTHORIZED, "Invalid signature"),
        Err(e) => {
            tracing::error!("Signature verification error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Signature verification failed");
        }
    }

    // Check payment status
    if event.data.object.payment_status != "paid" {
        return (StatusCode::OK, "Payment not completed");
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

    // Create license key
    let license = match queries::create_license_key(
        &conn,
        &payment_session.product_id,
        &crate::models::CreateLicenseKey {
            email: event.data.object.customer_email.clone(),
            expires_at: None,
        },
    ) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to create license: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create license");
        }
    };

    // Create device and issue JWT
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
        "Stripe payment completed: session={}, license={}",
        session_id,
        license.key
    );

    (StatusCode::OK, "OK")
}
