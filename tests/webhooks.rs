//! Webhook signature verification tests

mod common;

use common::*;
use paycheck::models::{LemonSqueezyConfig, StripeConfig};
use paycheck::payments::{LemonSqueezyClient, StripeClient};

// ============ Stripe Signature Verification Tests ============

fn create_stripe_test_client() -> StripeClient {
    let config = StripeConfig {
        secret_key: "sk_test_xxx".to_string(),
        publishable_key: "pk_test_xxx".to_string(),
        webhook_secret: "whsec_test_secret".to_string(),
    };
    StripeClient::new(&config)
}

/// Get current Unix timestamp as a string (for webhook signature tests)
fn current_timestamp() -> String {
    chrono::Utc::now().timestamp().to_string()
}

/// Get an old timestamp (for testing timestamp rejection)
fn old_timestamp() -> String {
    // 10 minutes ago - beyond the 5-minute tolerance
    (chrono::Utc::now().timestamp() - 600).to_string()
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

#[test]
fn test_stripe_valid_signature() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(payload, "whsec_test_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let result = client
        .verify_webhook_signature(payload, &signature_header)
        .expect("Verification should not error");

    assert!(result, "Valid signature should be accepted");
}

#[test]
fn test_stripe_invalid_signature() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";
    let timestamp = current_timestamp();
    // Use wrong secret to generate invalid signature
    let signature = compute_stripe_signature(payload, "wrong_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let result = client
        .verify_webhook_signature(payload, &signature_header)
        .expect("Verification should not error");

    assert!(!result, "Invalid signature should be rejected");
}

#[test]
fn test_stripe_modified_payload() {
    let client = create_stripe_test_client();
    let original_payload = b"{\"type\":\"checkout.session.completed\"}";
    let modified_payload = b"{\"type\":\"checkout.session.completed\",\"hacked\":true}";
    let timestamp = current_timestamp();
    // Sign the original payload
    let signature = compute_stripe_signature(original_payload, "whsec_test_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    // Verify with modified payload
    let result = client
        .verify_webhook_signature(modified_payload, &signature_header)
        .expect("Verification should not error");

    assert!(!result, "Modified payload should be rejected");
}

#[test]
fn test_stripe_old_timestamp_rejected() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";
    let timestamp = old_timestamp();
    // Valid signature but timestamp too old
    let signature = compute_stripe_signature(payload, "whsec_test_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let result = client
        .verify_webhook_signature(payload, &signature_header)
        .expect("Verification should not error");

    assert!(
        !result,
        "Old timestamp should be rejected (replay attack prevention)"
    );
}

#[test]
fn test_stripe_missing_timestamp() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";
    // Signature without timestamp
    let signature_header = "v1=somesignature";

    let result = client.verify_webhook_signature(payload, signature_header);

    assert!(result.is_err(), "Missing timestamp should error");
}

#[test]
fn test_stripe_missing_signature() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";
    // Header without v1 signature
    let signature_header = "t=1234567890";

    let result = client.verify_webhook_signature(payload, signature_header);

    assert!(result.is_err(), "Missing signature should error");
}

#[test]
fn test_stripe_malformed_header() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";

    let result = client.verify_webhook_signature(payload, "garbage");

    assert!(result.is_err(), "Malformed header should error");
}

#[test]
fn test_stripe_empty_signature_header() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";

    let result = client.verify_webhook_signature(payload, "");

    assert!(result.is_err(), "Empty header should error");
}

// ============ LemonSqueezy Signature Verification Tests ============

fn create_lemonsqueezy_test_client() -> LemonSqueezyClient {
    let config = LemonSqueezyConfig {
        api_key: "lskey_test_xxx".to_string(),
        store_id: "12345".to_string(),
        webhook_secret: "ls_test_secret".to_string(),
    };
    LemonSqueezyClient::new(&config)
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

#[test]
fn test_lemonsqueezy_valid_signature() {
    let client = create_lemonsqueezy_test_client();
    let payload = b"{\"meta\":{\"event_name\":\"order_created\"}}";
    let signature = compute_lemonsqueezy_signature(payload, "ls_test_secret");

    let result = client
        .verify_webhook_signature(payload, &signature)
        .expect("Verification should not error");

    assert!(result, "Valid signature should be accepted");
}

#[test]
fn test_lemonsqueezy_invalid_signature() {
    let client = create_lemonsqueezy_test_client();
    let payload = b"{\"meta\":{\"event_name\":\"order_created\"}}";
    // Use wrong secret
    let signature = compute_lemonsqueezy_signature(payload, "wrong_secret");

    let result = client
        .verify_webhook_signature(payload, &signature)
        .expect("Verification should not error");

    assert!(!result, "Invalid signature should be rejected");
}

#[test]
fn test_lemonsqueezy_modified_payload() {
    let client = create_lemonsqueezy_test_client();
    let original_payload = b"{\"meta\":{\"event_name\":\"order_created\"}}";
    let modified_payload = b"{\"meta\":{\"event_name\":\"order_created\",\"hacked\":true}}";
    // Sign original payload
    let signature = compute_lemonsqueezy_signature(original_payload, "ls_test_secret");

    // Verify with modified payload
    let result = client
        .verify_webhook_signature(modified_payload, &signature)
        .expect("Verification should not error");

    assert!(!result, "Modified payload should be rejected");
}

#[test]
fn test_lemonsqueezy_empty_signature() {
    let client = create_lemonsqueezy_test_client();
    let payload = b"{\"meta\":{\"event_name\":\"order_created\"}}";

    let result = client
        .verify_webhook_signature(payload, "")
        .expect("Verification should not error");

    assert!(!result, "Empty signature should be rejected");
}

#[test]
fn test_lemonsqueezy_wrong_format_signature() {
    let client = create_lemonsqueezy_test_client();
    let payload = b"{\"meta\":{\"event_name\":\"order_created\"}}";

    let result = client
        .verify_webhook_signature(payload, "not-a-valid-hex-signature")
        .expect("Verification should not error");

    assert!(!result, "Invalid format signature should be rejected");
}

// ============ Edge Cases ============

#[test]
fn test_stripe_large_payload() {
    let client = create_stripe_test_client();
    // Create a large payload
    let large_data = "x".repeat(100_000);
    let payload = format!("{{\"data\":\"{}\"}}", large_data);
    let payload_bytes = payload.as_bytes();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(payload_bytes, "whsec_test_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let result = client
        .verify_webhook_signature(payload_bytes, &signature_header)
        .expect("Verification should not error");

    assert!(
        result,
        "Large payload with valid signature should be accepted"
    );
}

#[test]
fn test_lemonsqueezy_large_payload() {
    let client = create_lemonsqueezy_test_client();
    // Create a large payload
    let large_data = "x".repeat(100_000);
    let payload = format!("{{\"data\":\"{}\"}}", large_data);
    let payload_bytes = payload.as_bytes();
    let signature = compute_lemonsqueezy_signature(payload_bytes, "ls_test_secret");

    let result = client
        .verify_webhook_signature(payload_bytes, &signature)
        .expect("Verification should not error");

    assert!(
        result,
        "Large payload with valid signature should be accepted"
    );
}

#[test]
fn test_stripe_binary_payload() {
    let client = create_stripe_test_client();
    // Binary data in payload
    let payload = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(payload, "whsec_test_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let result = client
        .verify_webhook_signature(payload, &signature_header)
        .expect("Verification should not error");

    assert!(
        result,
        "Binary payload with valid signature should be accepted"
    );
}

#[test]
fn test_lemonsqueezy_binary_payload() {
    let client = create_lemonsqueezy_test_client();
    let payload = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
    let signature = compute_lemonsqueezy_signature(payload, "ls_test_secret");

    let result = client
        .verify_webhook_signature(payload, &signature)
        .expect("Verification should not error");

    assert!(
        result,
        "Binary payload with valid signature should be accepted"
    );
}

#[test]
fn test_stripe_unicode_in_payload() {
    let client = create_stripe_test_client();
    let payload = "{\"customer_name\":\"日本語\",\"emoji\":\"🎉\"}".as_bytes();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(payload, "whsec_test_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let result = client
        .verify_webhook_signature(payload, &signature_header)
        .expect("Verification should not error");

    assert!(
        result,
        "Unicode payload with valid signature should be accepted"
    );
}

// ============ Webhook Replay Attack Prevention Tests ============

/// Test that replaying a renewal webhook does NOT extend the license twice.
/// This is a regression test for the LemonSqueezy replay vulnerability.
/// The test is provider-agnostic - it tests the underlying process_renewal logic.
#[test]
fn test_renewal_webhook_replay_prevented() {
    use axum::http::StatusCode;
    use paycheck::handlers::webhooks::common::process_renewal;

    let conn = setup_test_db();
    let master_key = test_master_key();

    // Create test hierarchy
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

    // Create license with short expiration (7 days from now)
    let initial_expiration = now() + (7 * 86400);
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        &project.license_key_prefix,
        Some(initial_expiration),
        &master_key,
    );

    // Simulate a renewal webhook with a unique event ID
    let event_id = "invoice_12345";
    let subscription_id = "sub_test_123";

    // First renewal should succeed and extend the license
    let (status1, _msg1) = process_renewal(
        &conn,
        "test_provider",
        &product,
        &license.id,
        &license.key,
        subscription_id,
        Some(event_id),
    );
    assert_eq!(status1, StatusCode::OK, "First renewal should succeed");

    // Check license was extended (product has 365 day license_exp_days)
    let updated_license = queries::get_license_key_by_id(&conn, &license.id, &master_key)
        .expect("Query should succeed")
        .expect("License should exist");
    let first_expiration = updated_license.expires_at.expect("Should have expiration");
    assert!(
        first_expiration > initial_expiration,
        "License expiration should be extended after first renewal"
    );

    // Wait a moment to ensure timestamps differ
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Replay the SAME webhook (same event_id)
    let (status2, msg2) = process_renewal(
        &conn,
        "test_provider",
        &product,
        &license.id,
        &license.key,
        subscription_id,
        Some(event_id), // Same event ID = replay
    );

    // Replay should be rejected (idempotent - already processed)
    assert_eq!(
        status2,
        StatusCode::OK,
        "Replay should return OK (idempotent)"
    );
    assert!(
        msg2.contains("Already processed") || msg2.contains("Duplicate"),
        "Replay should indicate already processed, got: {}",
        msg2
    );

    // Verify license expiration was NOT extended again
    let final_license = queries::get_license_key_by_id(&conn, &license.id, &master_key)
        .expect("Query should succeed")
        .expect("License should exist");
    let final_expiration = final_license.expires_at.expect("Should have expiration");

    assert_eq!(
        first_expiration, final_expiration,
        "License expiration should NOT change on replay"
    );
}

/// Test that different event IDs are processed independently (not blocked as replays)
#[test]
fn test_different_renewal_events_both_processed() {
    use axum::http::StatusCode;
    use paycheck::handlers::webhooks::common::process_renewal;

    let conn = setup_test_db();
    let master_key = test_master_key();

    // Create test hierarchy
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

    let initial_expiration = now() + (7 * 86400);
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        &project.license_key_prefix,
        Some(initial_expiration),
        &master_key,
    );

    let subscription_id = "sub_test_123";

    // First renewal event
    let (status1, _) = process_renewal(
        &conn,
        "test_provider",
        &product,
        &license.id,
        &license.key,
        subscription_id,
        Some("invoice_001"),
    );
    assert_eq!(status1, StatusCode::OK);

    // Second renewal event (different event ID - legitimate new renewal)
    let (status2, msg2) = process_renewal(
        &conn,
        "test_provider",
        &product,
        &license.id,
        &license.key,
        subscription_id,
        Some("invoice_002"), // Different event ID
    );
    assert_eq!(status2, StatusCode::OK);
    assert!(
        !msg2.contains("Already processed"),
        "Different event should be processed, not rejected as duplicate"
    );
}
