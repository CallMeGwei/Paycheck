//! Common webhook handling infrastructure for payment providers.
//!
//! This module provides a trait-based approach to unify Stripe and LemonSqueezy
//! webhook handlers, reducing code duplication while preserving provider-specific logic.

use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
};
use rusqlite::Connection;

use crate::crypto::MasterKey;
use crate::db::queries;
use crate::models::{CreateLicenseKey, Organization, PaymentSession, Product, Project};
use crate::util::LicenseExpirations;

/// Result type for webhook operations.
pub type WebhookResult = (StatusCode, &'static str);

/// Data extracted from a checkout/order completion event.
#[derive(Debug)]
pub struct CheckoutData {
    pub session_id: String,
    pub project_id: String,
    pub customer_id: Option<String>,
    pub subscription_id: Option<String>,
    /// Provider's order/checkout session ID (Stripe: cs_xxx, LemonSqueezy: order ID)
    pub order_id: Option<String>,
}

/// Data extracted from a subscription renewal event.
#[derive(Debug)]
pub struct RenewalData {
    pub subscription_id: String,
    /// Whether this is an actual renewal vs initial subscription creation
    pub is_renewal: bool,
    pub is_paid: bool,
}

/// Data extracted from a subscription cancellation event.
#[derive(Debug)]
pub struct CancellationData {
    pub subscription_id: String,
}

/// Parsed webhook event with provider-agnostic data.
#[derive(Debug)]
pub enum WebhookEvent {
    /// Initial checkout/order completed - creates license
    CheckoutCompleted(CheckoutData),
    /// Subscription renewed - extends license
    SubscriptionRenewed(RenewalData),
    /// Subscription cancelled - license expires naturally
    SubscriptionCancelled(CancellationData),
    /// Event type not relevant to license management
    Ignored,
}

/// Trait for payment provider webhook handling.
///
/// Implementors provide provider-specific parsing and signature verification,
/// while the common processing logic handles license creation/renewal.
pub trait WebhookProvider: Send + Sync {
    /// Provider name for logging and database storage (e.g., "stripe", "lemonsqueezy")
    fn provider_name(&self) -> &'static str;

    /// Extract signature from request headers.
    fn extract_signature(&self, headers: &HeaderMap) -> Result<String, WebhookResult>;

    /// Verify webhook signature against organization configuration.
    fn verify_signature(
        &self,
        org: &Organization,
        master_key: &MasterKey,
        body: &Bytes,
        signature: &str,
    ) -> Result<bool, WebhookResult>;

    /// Parse the webhook payload into a provider-agnostic event.
    fn parse_event(&self, body: &Bytes) -> Result<WebhookEvent, WebhookResult>;
}

/// Process a checkout completion event - creates license and device.
///
/// Uses atomic compare-and-swap to prevent race conditions where multiple concurrent
/// webhook deliveries could create multiple licenses from a single payment.
pub fn process_checkout(
    conn: &Connection,
    provider: &str,
    project: &Project,
    payment_session: &PaymentSession,
    product: &Product,
    data: &CheckoutData,
    master_key: &MasterKey,
) -> WebhookResult {
    // Atomically claim this payment session BEFORE creating any resources.
    // This prevents race conditions where concurrent webhooks could all create licenses.
    match queries::try_claim_payment_session(conn, &data.session_id) {
        Ok(true) => {
            // Successfully claimed - proceed with license creation
        }
        Ok(false) => {
            // Already claimed by another request
            return (StatusCode::OK, "Already processed");
        }
        Err(e) => {
            tracing::error!("Failed to claim payment session: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    }

    // Compute expirations from product settings
    let now = chrono::Utc::now().timestamp();
    let exps = LicenseExpirations::from_product(product, now);

    // Create license key
    let license = match queries::create_license_key(
        conn,
        &project.id,
        &payment_session.product_id,
        &project.license_key_prefix,
        &CreateLicenseKey {
            customer_id: payment_session.customer_id.clone(),
            expires_at: exps.license_exp,
            updates_expires_at: exps.updates_exp,
            payment_provider: Some(provider.to_string()),
            payment_provider_customer_id: data.customer_id.clone(),
            payment_provider_subscription_id: data.subscription_id.clone(),
            payment_provider_order_id: data.order_id.clone(),
        },
        master_key,
    ) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to create license: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create license");
        }
    };

    // Link license to payment session for efficient callback lookup
    if let Err(e) = queries::set_payment_session_license(conn, &data.session_id, &license.id) {
        tracing::error!("Failed to link license to session: {}", e);
        // Non-fatal - callback will fall back to search
    }

    // Create device
    let jti = uuid::Uuid::new_v4().to_string();
    if let Err(e) = queries::create_device(
        conn,
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
    if let Err(e) = queries::increment_activation_count(conn, &license.id) {
        tracing::error!("Failed to increment activation count: {}", e);
    }

    tracing::info!(
        "{} checkout completed: session={}, license=[REDACTED], subscription={:?}",
        provider,
        data.session_id,
        data.subscription_id
    );

    (StatusCode::OK, "OK")
}

/// Process a subscription renewal event - extends license expiration.
pub fn process_renewal(
    conn: &Connection,
    provider: &str,
    product: &Product,
    license_id: &str,
    license_key: &str,
    subscription_id: &str,
) -> WebhookResult {
    let now = chrono::Utc::now().timestamp();
    let exps = LicenseExpirations::from_product(product, now);

    if let Err(e) = queries::extend_license_expiration(conn, license_id, exps.license_exp, exps.updates_exp) {
        tracing::error!("Failed to extend license: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to extend license");
    }

    tracing::info!(
        "{} subscription renewed: subscription={}, license={}, new_expires_at={:?}",
        provider,
        subscription_id,
        license_key,
        exps.license_exp
    );

    (StatusCode::OK, "OK")
}

/// Process a subscription cancellation event - just logs, license expires naturally.
pub fn process_cancellation(
    provider: &str,
    license_key: &str,
    license_expires_at: Option<i64>,
    subscription_id: &str,
) -> WebhookResult {
    tracing::info!(
        "{} subscription cancelled: subscription={}, license={}, expires_at={:?} (will expire naturally)",
        provider,
        subscription_id,
        license_key,
        license_expires_at
    );

    (StatusCode::OK, "OK")
}

/// Generic webhook handler that delegates to provider-specific implementations.
pub async fn handle_webhook<P: WebhookProvider>(
    provider: &P,
    state: &crate::db::AppState,
    headers: HeaderMap,
    body: Bytes,
) -> WebhookResult {
    // Extract signature
    let signature = match provider.extract_signature(&headers) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Parse the event
    let event = match provider.parse_event(&body) {
        Ok(e) => e,
        Err(e) => return e,
    };

    // Handle based on event type
    match event {
        WebhookEvent::CheckoutCompleted(data) => {
            handle_checkout(provider, state, &body, &signature, data).await
        }
        WebhookEvent::SubscriptionRenewed(data) => {
            handle_renewal(provider, state, &body, &signature, data).await
        }
        WebhookEvent::SubscriptionCancelled(data) => {
            handle_cancellation(provider, state, &body, &signature, data).await
        }
        WebhookEvent::Ignored => (StatusCode::OK, "Event ignored"),
    }
}

async fn handle_checkout<P: WebhookProvider>(
    provider: &P,
    state: &crate::db::AppState,
    body: &Bytes,
    signature: &str,
    data: CheckoutData,
) -> WebhookResult {
    let conn = match state.db.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB connection error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    let project = match queries::get_project_by_id(&conn, &data.project_id) {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::OK, "Project not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Get organization for payment config
    let org = match queries::get_organization_by_id(&conn, &project.org_id) {
        Ok(Some(o)) => o,
        Ok(None) => return (StatusCode::OK, "Organization not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Verify signature
    match provider.verify_signature(&org, &state.master_key, body, signature) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::UNAUTHORIZED, "Invalid signature"),
        Err(e) => return e,
    }

    // Get payment session
    let payment_session = match queries::get_payment_session(&conn, &data.session_id) {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::OK, "Payment session not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Get product
    let product = match queries::get_product_by_id(&conn, &payment_session.product_id) {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::OK, "Product not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    process_checkout(&conn, provider.provider_name(), &project, &payment_session, &product, &data, &state.master_key)
}

async fn handle_renewal<P: WebhookProvider>(
    provider: &P,
    state: &crate::db::AppState,
    body: &Bytes,
    signature: &str,
    data: RenewalData,
) -> WebhookResult {
    // Skip if not a renewal (initial subscription handled by checkout)
    if !data.is_renewal {
        return (StatusCode::OK, "Initial subscription - handled by checkout");
    }

    if !data.is_paid {
        return (StatusCode::OK, "Invoice not paid");
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB connection error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Find license by subscription ID
    let license = match queries::get_license_key_by_subscription(&conn, provider.provider_name(), &data.subscription_id, &state.master_key) {
        Ok(Some(l)) => l,
        Ok(None) => {
            tracing::warn!("No license found for {} subscription: {}", provider.provider_name(), data.subscription_id);
            return (StatusCode::OK, "License not found for subscription");
        }
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Get product and project for signature verification
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

    // Get organization for payment config
    let org = match queries::get_organization_by_id(&conn, &project.org_id) {
        Ok(Some(o)) => o,
        Ok(None) => return (StatusCode::OK, "Organization not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Verify signature
    match provider.verify_signature(&org, &state.master_key, body, signature) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::UNAUTHORIZED, "Invalid signature"),
        Err(e) => return e,
    }

    process_renewal(&conn, provider.provider_name(), &product, &license.id, &license.key, &data.subscription_id)
}

async fn handle_cancellation<P: WebhookProvider>(
    provider: &P,
    state: &crate::db::AppState,
    body: &Bytes,
    signature: &str,
    data: CancellationData,
) -> WebhookResult {
    let conn = match state.db.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB connection error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Find license by subscription ID
    let license = match queries::get_license_key_by_subscription(&conn, provider.provider_name(), &data.subscription_id, &state.master_key) {
        Ok(Some(l)) => l,
        Ok(None) => {
            tracing::warn!("No license found for {} subscription: {}", provider.provider_name(), data.subscription_id);
            return (StatusCode::OK, "License not found for subscription");
        }
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Get product and project for signature verification
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

    // Get organization for payment config
    let org = match queries::get_organization_by_id(&conn, &project.org_id) {
        Ok(Some(o)) => o,
        Ok(None) => return (StatusCode::OK, "Organization not found"),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Verify signature
    match provider.verify_signature(&org, &state.master_key, body, signature) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::UNAUTHORIZED, "Invalid signature"),
        Err(e) => return e,
    }

    process_cancellation(provider.provider_name(), &license.key, license.expires_at, &data.subscription_id)
}
