//! Common webhook handling infrastructure for payment providers.
//!
//! This module provides a trait-based approach to unify Stripe and LemonSqueezy
//! webhook handlers, reducing code duplication while preserving provider-specific logic.

use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
};
use rusqlite::Connection;

use crate::crypto::{EmailHasher, MasterKey};
use crate::db::{AppState, queries};
use crate::error::AppError;
use crate::models::{CreateLicense, License, Organization, PaymentSession, Product, Project};
use crate::util::LicenseExpirations;

/// Helper to unwrap DB query results with consistent error handling.
fn db_lookup<T>(
    result: Result<Option<T>, AppError>,
    not_found_msg: &'static str,
) -> Result<T, WebhookResult> {
    match result {
        Ok(Some(v)) => Ok(v),
        Ok(None) => Err((StatusCode::OK, not_found_msg)),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"))
        }
    }
}

/// Helper for subscription lookup with warning log on not found.
fn lookup_license_by_subscription<P: WebhookProvider>(
    provider: &P,
    conn: &Connection,
    subscription_id: &str,
) -> Result<License, WebhookResult> {
    match queries::get_license_by_subscription(conn, provider.provider_name(), subscription_id) {
        Ok(Some(l)) => Ok(l),
        Ok(None) => {
            tracing::warn!(
                "No license found for {} subscription: {}",
                provider.provider_name(),
                subscription_id
            );
            Err((StatusCode::OK, "License not found for subscription"))
        }
        Err(e) => {
            tracing::error!("DB error: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"))
        }
    }
}

/// Result type for webhook operations.
pub type WebhookResult = (StatusCode, &'static str);

/// Data extracted from a checkout/order completion event.
#[derive(Debug)]
pub struct CheckoutData {
    pub session_id: String,
    pub project_id: String,
    pub customer_id: Option<String>,
    /// Customer email from payment provider (for license recovery via email)
    pub customer_email: Option<String>,
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
    /// Unique event/invoice ID for replay prevention
    pub event_id: Option<String>,
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

/// Process a checkout completion event - creates license only.
///
/// Device creation is deferred to activation time (/redeem endpoint).
/// Uses atomic compare-and-swap to prevent race conditions where multiple concurrent
/// webhook deliveries could create multiple licenses from a single payment.
pub fn process_checkout(
    conn: &mut Connection,
    email_hasher: &EmailHasher,
    provider: &str,
    project: &Project,
    payment_session: &PaymentSession,
    product: &Product,
    data: &CheckoutData,
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

    // Compute email hash for license recovery via email
    let email_hash = data.customer_email.as_ref().map(|e| email_hasher.hash(e));

    if email_hash.is_none() {
        tracing::warn!(
            "No email in checkout for session {} - license will not be recoverable via email",
            data.session_id
        );
    }

    // Compute expirations from product settings
    let now = chrono::Utc::now().timestamp();
    let exps = LicenseExpirations::from_product(product, now);

    // Create license (no user-facing key - email hash is the identity)
    let license = match queries::create_license(
        conn,
        &project.id,
        &payment_session.product_id,
        &CreateLicense {
            email_hash,
            customer_id: payment_session.customer_id.clone(),
            expires_at: exps.license_exp,
            updates_expires_at: exps.updates_exp,
            payment_provider: Some(provider.to_string()),
            payment_provider_customer_id: data.customer_id.clone(),
            payment_provider_subscription_id: data.subscription_id.clone(),
            payment_provider_order_id: data.order_id.clone(),
        },
    ) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to create license: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create license",
            );
        }
    };

    // Link license to payment session for efficient callback lookup
    if let Err(e) = queries::set_payment_session_license(conn, &data.session_id, &license.id) {
        tracing::error!("Failed to link license to session: {}", e);
        // Non-fatal - callback will fall back to search
    }

    // NOTE: Device creation is deferred to activation time (/redeem endpoint).
    // This separates purchase from activation - user may buy on phone, activate on desktop.

    tracing::info!(
        "{} checkout completed: session={}, license_id={}, subscription={:?}",
        provider,
        data.session_id,
        license.id,
        data.subscription_id
    );

    (StatusCode::OK, "OK")
}

/// Process a subscription renewal event - extends license expiration.
///
/// The `event_id` parameter is used for replay attack prevention - if the same
/// event_id is processed twice, the second call returns "Already processed".
pub fn process_renewal(
    conn: &Connection,
    provider: &str,
    product: &Product,
    license_id: &str,
    subscription_id: &str,
    event_id: Option<&str>,
) -> WebhookResult {
    // Replay attack prevention: check if we've already processed this event
    if let Some(eid) = event_id {
        match queries::try_record_webhook_event(conn, provider, eid) {
            Ok(true) => {
                // New event - proceed with processing
            }
            Ok(false) => {
                // Already processed - idempotent response
                return (StatusCode::OK, "Already processed");
            }
            Err(e) => {
                tracing::error!("Failed to record webhook event: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
            }
        }
    }

    let now = chrono::Utc::now().timestamp();
    let exps = LicenseExpirations::from_product(product, now);

    if let Err(e) =
        queries::extend_license_expiration(conn, license_id, exps.license_exp, exps.updates_exp)
    {
        tracing::error!("Failed to extend license: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to extend license",
        );
    }

    tracing::info!(
        "{} subscription renewed: subscription={}, license_id={}, new_expires_at={:?}",
        provider,
        subscription_id,
        license_id,
        exps.license_exp
    );

    (StatusCode::OK, "OK")
}

/// Process a subscription cancellation event - just logs, license expires naturally.
pub fn process_cancellation(
    provider: &str,
    license_id: &str,
    license_expires_at: Option<i64>,
    subscription_id: &str,
) -> WebhookResult {
    tracing::info!(
        "{} subscription cancelled: subscription={}, license_id={}, expires_at={:?} (will expire naturally)",
        provider,
        subscription_id,
        license_id,
        license_expires_at
    );

    (StatusCode::OK, "OK")
}

/// Generic webhook handler that delegates to provider-specific implementations.
pub async fn handle_webhook<P: WebhookProvider>(
    provider: &P,
    state: &AppState,
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
            handle_checkout(provider, state, &body, &signature, data)
                .await
                .unwrap_or_else(|e| e)
        }
        WebhookEvent::SubscriptionRenewed(data) => {
            handle_renewal(provider, state, &body, &signature, data)
                .await
                .unwrap_or_else(|e| e)
        }
        WebhookEvent::SubscriptionCancelled(data) => {
            handle_cancellation(provider, state, &body, &signature, data)
                .await
                .unwrap_or_else(|e| e)
        }
        WebhookEvent::Ignored => (StatusCode::OK, "Event ignored"),
    }
}

async fn handle_checkout<P: WebhookProvider>(
    provider: &P,
    state: &AppState,
    body: &Bytes,
    signature: &str,
    data: CheckoutData,
) -> Result<WebhookResult, WebhookResult> {
    let mut conn = state.db.get().map_err(|e| {
        tracing::error!("DB connection error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    let project = db_lookup(
        queries::get_project_by_id(&conn, &data.project_id),
        "Project not found",
    )?;

    let org = db_lookup(
        queries::get_organization_by_id(&conn, &project.org_id),
        "Organization not found",
    )?;

    // Verify signature
    match provider.verify_signature(&org, &state.master_key, body, signature) {
        Ok(true) => {}
        Ok(false) => return Err((StatusCode::UNAUTHORIZED, "Invalid signature")),
        Err(e) => return Err(e),
    }

    let payment_session = db_lookup(
        queries::get_payment_session(&conn, &data.session_id),
        "Payment session not found",
    )?;

    let product = db_lookup(
        queries::get_product_by_id(&conn, &payment_session.product_id),
        "Product not found",
    )?;

    Ok(process_checkout(
        &mut conn,
        &state.email_hasher,
        provider.provider_name(),
        &project,
        &payment_session,
        &product,
        &data,
    ))
}

async fn handle_renewal<P: WebhookProvider>(
    provider: &P,
    state: &AppState,
    body: &Bytes,
    signature: &str,
    data: RenewalData,
) -> Result<WebhookResult, WebhookResult> {
    // Skip if not a renewal (initial subscription handled by checkout)
    if !data.is_renewal {
        return Ok((StatusCode::OK, "Initial subscription - handled by checkout"));
    }

    if !data.is_paid {
        return Ok((StatusCode::OK, "Invoice not paid"));
    }

    let conn = state.db.get().map_err(|e| {
        tracing::error!("DB connection error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    let license = lookup_license_by_subscription(provider, &conn, &data.subscription_id)?;
    let product = db_lookup(
        queries::get_product_by_id(&conn, &license.product_id),
        "Product not found",
    )?;
    let project = db_lookup(
        queries::get_project_by_id(&conn, &product.project_id),
        "Project not found",
    )?;
    let org = db_lookup(
        queries::get_organization_by_id(&conn, &project.org_id),
        "Organization not found",
    )?;

    // Verify signature
    match provider.verify_signature(&org, &state.master_key, body, signature) {
        Ok(true) => {}
        Ok(false) => return Err((StatusCode::UNAUTHORIZED, "Invalid signature")),
        Err(e) => return Err(e),
    }

    Ok(process_renewal(
        &conn,
        provider.provider_name(),
        &product,
        &license.id,
        &data.subscription_id,
        data.event_id.as_deref(),
    ))
}

async fn handle_cancellation<P: WebhookProvider>(
    provider: &P,
    state: &AppState,
    body: &Bytes,
    signature: &str,
    data: CancellationData,
) -> Result<WebhookResult, WebhookResult> {
    let conn = state.db.get().map_err(|e| {
        tracing::error!("DB connection error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    let license = lookup_license_by_subscription(provider, &conn, &data.subscription_id)?;
    let product = db_lookup(
        queries::get_product_by_id(&conn, &license.product_id),
        "Product not found",
    )?;
    let project = db_lookup(
        queries::get_project_by_id(&conn, &product.project_id),
        "Project not found",
    )?;
    let org = db_lookup(
        queries::get_organization_by_id(&conn, &project.org_id),
        "Organization not found",
    )?;

    // Verify signature
    match provider.verify_signature(&org, &state.master_key, body, signature) {
        Ok(true) => {}
        Ok(false) => return Err((StatusCode::UNAUTHORIZED, "Invalid signature")),
        Err(e) => return Err(e),
    }

    Ok(process_cancellation(
        provider.provider_name(),
        &license.id,
        license.expires_at,
        &data.subscription_id,
    ))
}
