//! Security tests for webhook error handling.
//!
//! These tests verify that webhook endpoints handle configuration errors gracefully
//! without leaking internal state or causing retry storms from payment providers.

#[path = "../common/mod.rs"]
mod common;

use axum::{Router, body::Body, http::Request, routing::post};
use common::*;
use paycheck::db::queries;
use paycheck::handlers::webhooks::{handle_lemonsqueezy_webhook, handle_stripe_webhook};
use serde_json::json;
use tower::ServiceExt;

fn webhook_app(state: paycheck::db::AppState) -> Router {
    Router::new()
        .route("/webhook/stripe", post(handle_stripe_webhook))
        .route("/webhook/lemonsqueezy", post(handle_lemonsqueezy_webhook))
        .with_state(state)
}

/// Helper to set CORRUPTED Stripe config for an organization.
/// This simulates a scenario where encrypted data is corrupted (e.g., master key changed
/// but data wasn't re-encrypted, or database corruption).
fn setup_corrupted_stripe_config(conn: &rusqlite::Connection, org_id: &str) {
    // Create bytes that look like encrypted data (start with ENC1 magic) but will fail
    // AES-GCM decryption because the ciphertext is garbage
    let mut corrupted_bytes = Vec::new();
    corrupted_bytes.extend_from_slice(b"ENC1"); // Magic bytes
    corrupted_bytes.extend_from_slice(&[0u8; 12]); // Fake nonce (12 bytes)
    corrupted_bytes.extend_from_slice(b"corrupted_ciphertext_garbage_data"); // Invalid ciphertext

    queries::update_organization_encrypted_configs(
        conn,
        org_id,
        Some(&corrupted_bytes),
        None,
        None,
    )
    .expect("Failed to set corrupted Stripe config");
}

fn compute_stripe_signature(payload: &[u8], secret: &str, timestamp: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(signed_payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn current_timestamp() -> String {
    chrono::Utc::now().timestamp().to_string()
}

// ============ VULNERABILITY TEST ============

/// SECURITY TEST: Webhook with corrupted config should NOT return 500.
///
/// This test verifies a security issue where an organization with corrupted
/// payment provider configuration causes the webhook to return HTTP 500.
///
/// Why this is a problem:
/// 1. Payment providers (Stripe, LemonSqueezy) retry on 5xx errors indefinitely
/// 2. This creates a "retry storm" that wastes resources
/// 3. It leaks internal state (attacker can probe which orgs have broken configs)
/// 4. It distinguishes "config exists but is broken" from "no config" (info leak)
///
/// Expected behavior: Return 200 OK (or 401) so provider doesn't retry.
/// Current behavior (vulnerability): Returns 500 INTERNAL_SERVER_ERROR.
#[tokio::test]
async fn test_stripe_webhook_corrupted_config_should_not_return_500() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");

        // Set up CORRUPTED Stripe config - this is the key difference
        setup_corrupted_stripe_config(&conn, &org.id);

        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&conn, &product.id, None);

        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    // Create a valid-format webhook payload
    let payload = json!({
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_123",
                "payment_status": "paid",
                "customer": "cus_test",
                "subscription": "sub_test_123",
                "metadata": {
                    "paycheck_session_id": session_id,
                    "project_id": project_id
                },
                "customer_email": "test@example.com"
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    // Create a valid-looking signature (won't verify, but that's OK - we won't get that far)
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "any_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", signature_header)
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();

    // THE VULNERABILITY: This currently returns 500, but should return 200 or 401
    // If this test PASSES (status != 500), the vulnerability has been fixed
    // If this test FAILS (status == 500), the vulnerability exists
    assert_ne!(
        status,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "SECURITY VULNERABILITY: Webhook with corrupted config returns 500, \
         which causes payment providers to retry indefinitely and leaks internal state. \
         Should return 200 OK or 401 UNAUTHORIZED instead."
    );
}

/// Verify that a properly configured webhook works (control test).
/// This ensures our test setup is correct.
#[tokio::test]
async fn test_stripe_webhook_valid_config_works() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");

        // Set up VALID Stripe config
        setup_stripe_config(&conn, &org.id, &master_key);

        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&conn, &product.id, None);

        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    let payload = json!({
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_123",
                "payment_status": "paid",
                "customer": "cus_test",
                "subscription": "sub_test_123",
                "metadata": {
                    "paycheck_session_id": session_id,
                    "project_id": project_id
                },
                "customer_email": "test@example.com"
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    // Use the correct webhook secret from setup_stripe_config
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "whsec_test_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", signature_header)
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "Valid webhook with correct config should return 200 OK"
    );
}

// ============ LemonSqueezy Tests ============

/// Helper to set CORRUPTED LemonSqueezy config for an organization.
fn setup_corrupted_lemonsqueezy_config(conn: &rusqlite::Connection, org_id: &str) {
    let mut corrupted_bytes = Vec::new();
    corrupted_bytes.extend_from_slice(b"ENC1"); // Magic bytes
    corrupted_bytes.extend_from_slice(&[0u8; 12]); // Fake nonce (12 bytes)
    corrupted_bytes.extend_from_slice(b"corrupted_ciphertext_garbage_data"); // Invalid ciphertext

    queries::update_organization_encrypted_configs(
        conn,
        org_id,
        None, // No Stripe config
        Some(&corrupted_bytes), // Corrupted LemonSqueezy config
        None,
    )
    .expect("Failed to set corrupted LemonSqueezy config");
}

fn compute_lemonsqueezy_signature(payload: &[u8], secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

/// SECURITY TEST: LemonSqueezy webhook with corrupted config should NOT return 500.
#[tokio::test]
async fn test_lemonsqueezy_webhook_corrupted_config_should_not_return_500() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");

        // Set up CORRUPTED LemonSqueezy config
        setup_corrupted_lemonsqueezy_config(&conn, &org.id);

        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&conn, &product.id, None);

        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    // Create a valid-format LemonSqueezy webhook payload
    let payload = json!({
        "meta": {
            "event_name": "order_created",
            "custom_data": {
                "paycheck_session_id": session_id,
                "project_id": project_id
            }
        },
        "data": {
            "id": "12345",
            "attributes": {
                "first_order_item": {
                    "product_id": 123
                },
                "user_email": "test@example.com",
                "customer_id": 456,
                "status": "paid"
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    // Create a signature (won't verify, but we won't get that far)
    let signature = compute_lemonsqueezy_signature(&payload_bytes, "any_secret");

    let app = webhook_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/lemonsqueezy")
                .header("content-type", "application/json")
                .header("x-signature", signature)
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();

    assert_ne!(
        status,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "SECURITY VULNERABILITY: LemonSqueezy webhook with corrupted config returns 500, \
         which causes payment providers to retry indefinitely and leaks internal state. \
         Should return 200 OK or 401 UNAUTHORIZED instead."
    );
}
