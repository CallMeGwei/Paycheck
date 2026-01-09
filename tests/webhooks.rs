//! Webhook signature verification and business logic tests

mod common;

use common::*;
use paycheck::handlers::webhooks::common::{
    CheckoutData, process_cancellation, process_checkout, process_renewal,
};
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
        Some(initial_expiration),
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
        subscription_id,
        Some(event_id),
    );
    assert_eq!(status1, StatusCode::OK, "First renewal should succeed");

    // Check license was extended (product has 365 day license_exp_days)
    let updated_license = queries::get_license_by_id(&conn, &license.id)
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
    let final_license = queries::get_license_by_id(&conn, &license.id)
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
        Some(initial_expiration),
    );

    let subscription_id = "sub_test_123";

    // First renewal event
    let (status1, _) = process_renewal(
        &conn,
        "test_provider",
        &product,
        &license.id,
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
        subscription_id,
        Some("invoice_002"), // Different event ID
    );
    assert_eq!(status2, StatusCode::OK);
    assert!(
        !msg2.contains("Already processed"),
        "Different event should be processed, not rejected as duplicate"
    );
}

// ============ Checkout Business Logic Tests ============

#[test]
fn test_checkout_creates_license_and_device() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

    // Create payment session (no device info - that's at activation time)
    let session = create_test_payment_session(&conn, &product.id, Some("cust_test"), None);

    let checkout_data = CheckoutData {
        session_id: session.id.clone(),
        project_id: project.id.clone(),
        customer_id: Some("cust_stripe".to_string()),
        customer_email: Some("test@example.com".to_string()),
        subscription_id: Some("sub_123".to_string()),
        order_id: Some("cs_test_123".to_string()),
    };

    let (status, msg) = process_checkout(
        &mut conn,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );

    assert_eq!(status, StatusCode::OK);
    assert_eq!(msg, "OK");

    // Verify license was created
    let updated_session = queries::get_payment_session(&conn, &session.id)
        .unwrap()
        .unwrap();
    assert!(updated_session.completed);
    assert!(updated_session.license_id.is_some());

    // Verify license has correct metadata
    let license_id = updated_session.license_id.unwrap();
    let license = queries::get_license_by_id(&conn, &license_id)
        .unwrap()
        .unwrap();
    assert_eq!(license.payment_provider.as_deref(), Some("stripe"));
    assert_eq!(
        license.payment_provider_subscription_id.as_deref(),
        Some("sub_123")
    );
    assert_eq!(
        license.payment_provider_order_id.as_deref(),
        Some("cs_test_123")
    );

    // Device creation is deferred to activation time (/redeem/key)
    // Verify NO device was created during checkout
    let devices = queries::list_devices_for_license(&conn, &license_id).unwrap();
    assert_eq!(
        devices.len(),
        0,
        "No device should be created at checkout - activation creates the device"
    );
}

#[test]
fn test_checkout_concurrent_webhooks_create_only_one_license() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

    let session = create_test_payment_session(&conn, &product.id, None, None);

    let checkout_data = CheckoutData {
        session_id: session.id.clone(),
        project_id: project.id.clone(),
        customer_id: None,
        customer_email: Some("test@example.com".to_string()),
        subscription_id: None,
        order_id: None,
    };

    // First call should succeed
    let (status1, msg1) = process_checkout(
        &mut conn,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(msg1, "OK");

    // Second call with same session should be rejected
    let (status2, msg2) = process_checkout(
        &mut conn,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(msg2, "Already processed");

    // Verify only one license exists for the session
    let updated_session = queries::get_payment_session(&conn, &session.id)
        .unwrap()
        .unwrap();
    let license_id = updated_session.license_id.unwrap();

    // Device creation is deferred to activation time (/redeem/key)
    // Verify NO device was created during checkout
    let devices = queries::list_devices_for_license(&conn, &license_id).unwrap();
    assert_eq!(
        devices.len(),
        0,
        "No device should be created at checkout - device is created at activation time"
    );
}

#[test]
fn test_checkout_creates_license_with_product_expirations() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

    // Create product with specific expirations
    let input = CreateProduct {
        name: "Pro Plan".to_string(),
        tier: "pro".to_string(),
        license_exp_days: Some(30),  // 30 days
        updates_exp_days: Some(180), // 180 days
        activation_limit: 5,
        device_limit: 3,
        features: vec![],
    };
    let product = queries::create_product(&conn, &project.id, &input).unwrap();

    let session = create_test_payment_session(&conn, &product.id, None, None);

    let checkout_data = CheckoutData {
        session_id: session.id.clone(),
        project_id: project.id.clone(),
        customer_id: None,
        customer_email: Some("test@example.com".to_string()),
        subscription_id: None,
        order_id: None,
    };

    let before = now();
    let (status, _) = process_checkout(
        &mut conn,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );
    assert_eq!(status, StatusCode::OK);

    let updated_session = queries::get_payment_session(&conn, &session.id)
        .unwrap()
        .unwrap();
    let license = queries::get_license_by_id(
        &conn,
        &updated_session.license_id.unwrap(),
    )
    .unwrap()
    .unwrap();

    // License should expire in ~30 days
    let license_exp = license.expires_at.unwrap();
    assert!(license_exp >= before + (30 * 86400) - 5);
    assert!(license_exp <= before + (30 * 86400) + 5);

    // Updates should expire in ~180 days
    let updates_exp = license.updates_expires_at.unwrap();
    assert!(updates_exp >= before + (180 * 86400) - 5);
    assert!(updates_exp <= before + (180 * 86400) + 5);
}

#[test]
fn test_checkout_perpetual_license() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

    // Create product with no expiration (perpetual)
    let input = CreateProduct {
        name: "Lifetime".to_string(),
        tier: "lifetime".to_string(),
        license_exp_days: None, // Perpetual
        updates_exp_days: None,
        activation_limit: 5,
        device_limit: 3,
        features: vec![],
    };
    let product = queries::create_product(&conn, &project.id, &input).unwrap();

    let session = create_test_payment_session(&conn, &product.id, None, None);

    let checkout_data = CheckoutData {
        session_id: session.id.clone(),
        project_id: project.id.clone(),
        customer_id: None,
        customer_email: Some("test@example.com".to_string()),
        subscription_id: None,
        order_id: None,
    };

    let (status, _) = process_checkout(
        &mut conn,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );
    assert_eq!(status, StatusCode::OK);

    let updated_session = queries::get_payment_session(&conn, &session.id)
        .unwrap()
        .unwrap();
    let license = queries::get_license_by_id(
        &conn,
        &updated_session.license_id.unwrap(),
    )
    .unwrap()
    .unwrap();

    assert!(
        license.expires_at.is_none(),
        "Perpetual license has no expiration"
    );
    assert!(
        license.updates_expires_at.is_none(),
        "Perpetual license has no updates expiration"
    );
}

// ============ Renewal Business Logic Tests ============

#[test]
fn test_renewal_extends_license_expiration() {
    use axum::http::StatusCode;

    let conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

    // Create license expiring soon
    let initial_exp = now() + (7 * 86400); // 7 days from now
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(initial_exp),
    );

    let (status, _) = process_renewal(
        &conn,
        "stripe",
        &product,
        &license.id,
        "sub_123",
        Some("invoice_001"),
    );
    assert_eq!(status, StatusCode::OK);

    let updated = queries::get_license_by_id(&conn, &license.id)
        .unwrap()
        .unwrap();
    let new_exp = updated.expires_at.unwrap();

    // Product has 365-day license_exp_days, so new exp should be ~365 days from now
    let expected_min = now() + (365 * 86400) - 10;
    let expected_max = now() + (365 * 86400) + 10;
    assert!(
        new_exp >= expected_min && new_exp <= expected_max,
        "License should be extended by product expiration (365 days), got {} days",
        (new_exp - now()) / 86400
    );
}

#[test]
fn test_renewal_without_event_id_always_processes() {
    use axum::http::StatusCode;

    let conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(now() + 86400),
    );

    // First call without event_id
    let (status1, msg1) = process_renewal(
        &conn,
        "stripe",
        &product,
        &license.id,
        "sub_123",
        None, // No event_id - no replay prevention
    );
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(msg1, "OK");

    // Second call also processes (no replay prevention)
    let (status2, msg2) = process_renewal(
        &conn,
        "stripe",
        &product,
        &license.id,
        "sub_123",
        None,
    );
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(msg2, "OK");
}

// ============ Cancellation Business Logic Tests ============

#[test]
fn test_cancellation_returns_ok_without_modifying_license() {
    use axum::http::StatusCode;

    let conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

    let original_exp = now() + (30 * 86400);
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(original_exp),
    );

    let (status, msg) = process_cancellation("stripe", &license.id, license.expires_at, "sub_123");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(msg, "OK");

    // Verify license was NOT modified
    let unchanged = queries::get_license_by_id(&conn, &license.id)
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.expires_at, Some(original_exp));
    assert!(!unchanged.revoked);
}

// ============ Stripe HTTP Handler Tests ============

use axum::{Router, body::Body, http::Request, routing::post};
use paycheck::handlers::webhooks::{handle_lemonsqueezy_webhook, handle_stripe_webhook};
use serde_json::json;
use tower::ServiceExt;

fn webhook_app(state: paycheck::db::AppState) -> Router {
    Router::new()
        .route("/webhook/stripe", post(handle_stripe_webhook))
        .route("/webhook/lemonsqueezy", post(handle_lemonsqueezy_webhook))
        .with_state(state)
}

#[tokio::test]
async fn test_stripe_webhook_checkout_completed_creates_license() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        setup_stripe_config(&conn, &org.id, &master_key);

        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        let session = create_test_payment_session(&conn, &product.id, None, None);

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
                }
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "whsec_test_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state.clone());

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

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Verify license was created
    let conn = state.db.get().unwrap();
    let session = queries::get_payment_session(&conn, &session_id)
        .unwrap()
        .unwrap();
    assert!(session.completed);
    assert!(session.license_id.is_some());

    let license =
        queries::get_license_by_id(&conn, &session.license_id.unwrap())
            .unwrap()
            .unwrap();
    assert_eq!(license.payment_provider.as_deref(), Some("stripe"));
    assert_eq!(
        license.payment_provider_subscription_id.as_deref(),
        Some("sub_test_123")
    );
}

#[tokio::test]
async fn test_stripe_webhook_missing_signature_returns_error() {
    let state = create_test_app_state();

    let payload = json!({
        "type": "checkout.session.completed",
        "data": {"object": {}}
    });

    let app = webhook_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                // No stripe-signature header!
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_stripe_webhook_invalid_signature_returns_unauthorized() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        setup_stripe_config(&conn, &org.id, &master_key);
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&conn, &product.id, None, None);
        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    let payload = json!({
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_123",
                "payment_status": "paid",
                "metadata": {
                    "paycheck_session_id": session_id,
                    "project_id": project_id
                }
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let timestamp = current_timestamp();
    // Sign with wrong secret
    let signature = compute_stripe_signature(&payload_bytes, "wrong_secret", &timestamp);
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

    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_stripe_webhook_unpaid_checkout_ignored() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        setup_stripe_config(&conn, &org.id, &master_key);
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&conn, &product.id, None, None);
        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    let payload = json!({
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_123",
                "payment_status": "unpaid", // NOT paid
                "metadata": {
                    "paycheck_session_id": session_id,
                    "project_id": project_id
                }
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "whsec_test_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state.clone());

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

    // Returns OK but event is ignored
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Session should NOT be completed
    let conn = state.db.get().unwrap();
    let session = queries::get_payment_session(&conn, &session_id)
        .unwrap()
        .unwrap();
    assert!(!session.completed);
}

#[tokio::test]
async fn test_stripe_webhook_invoice_paid_extends_license() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_id: String;
    let original_exp: i64;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        setup_stripe_config(&conn, &org.id, &master_key);
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        // Create license with subscription
        original_exp = now() + (7 * 86400);
        let license = create_test_license_with_subscription(
            &conn,
            &project.id,
            &product.id,
            Some(original_exp),
            "stripe",
            "sub_test_renewal",
        );
        license_id = license.id.clone();
    }

    let payload = json!({
        "type": "invoice.paid",
        "data": {
            "object": {
                "id": "in_test_123",
                "subscription": "sub_test_renewal",
                "billing_reason": "subscription_cycle",
                "status": "paid"
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "whsec_test_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state.clone());

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

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Verify license was extended
    let conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&conn, &license_id)
        .unwrap()
        .unwrap();
    let new_exp = license.expires_at.unwrap();
    assert!(
        new_exp > original_exp,
        "License should be extended from {} to {}",
        original_exp,
        new_exp
    );
}

#[tokio::test]
async fn test_stripe_webhook_subscription_deleted_returns_ok() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_id: String;
    let original_exp: i64;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        setup_stripe_config(&conn, &org.id, &master_key);
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        original_exp = now() + (30 * 86400);
        let license = create_test_license_with_subscription(
            &conn,
            &project.id,
            &product.id,
            Some(original_exp),
            "stripe",
            "sub_cancel_test",
        );
        license_id = license.id.clone();
    }

    let payload = json!({
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_cancel_test",
                "customer": "cus_test",
                "status": "canceled"
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "whsec_test_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state.clone());

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

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // License should be unchanged (expires naturally)
    let conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&conn, &license_id)
        .unwrap()
        .unwrap();
    assert_eq!(license.expires_at, Some(original_exp));
    assert!(!license.revoked);
}

#[tokio::test]
async fn test_stripe_webhook_unknown_event_ignored() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        setup_stripe_config(&conn, &org.id, &master_key);
    }

    let payload = json!({
        "type": "payment_intent.created",
        "data": {"object": {"id": "pi_test"}}
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
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

    // Unknown events are ignored with 200 OK
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

// ============ LemonSqueezy HTTP Handler Tests ============

#[tokio::test]
async fn test_lemonsqueezy_webhook_order_created_creates_license() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        setup_lemonsqueezy_config(&conn, &org.id, &master_key);

        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        let session = create_test_payment_session(&conn, &product.id, None, None);

        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    let payload = json!({
        "meta": {
            "event_name": "order_created",
            "custom_data": {
                "paycheck_session_id": session_id,
                "project_id": project_id
            }
        },
        "data": {
            "id": "order_123",
            "attributes": {
                "status": "paid",
                "customer_id": 12345,
                "first_order_item": {
                    "subscription_id": 67890
                }
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_test_secret");

    let app = webhook_app(state.clone());

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

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Verify license was created
    let conn = state.db.get().unwrap();
    let session = queries::get_payment_session(&conn, &session_id)
        .unwrap()
        .unwrap();
    assert!(session.completed);
    assert!(session.license_id.is_some());

    let license =
        queries::get_license_by_id(&conn, &session.license_id.unwrap())
            .unwrap()
            .unwrap();
    assert_eq!(license.payment_provider.as_deref(), Some("lemonsqueezy"));
}

#[tokio::test]
async fn test_lemonsqueezy_webhook_missing_signature_returns_error() {
    let state = create_test_app_state();

    let payload = json!({
        "meta": {"event_name": "order_created"},
        "data": {"id": "123", "attributes": {}}
    });

    let app = webhook_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/lemonsqueezy")
                .header("content-type", "application/json")
                // No x-signature header!
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_lemonsqueezy_webhook_invalid_signature_returns_unauthorized() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        setup_lemonsqueezy_config(&conn, &org.id, &master_key);
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&conn, &product.id, None, None);

        // Use session_id and project_id in payload
        let payload = json!({
            "meta": {
                "event_name": "order_created",
                "custom_data": {
                    "paycheck_session_id": session.id,
                    "project_id": project.id
                }
            },
            "data": {
                "id": "order_123",
                "attributes": {
                    "status": "paid"
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        // Sign with wrong secret
        let signature = compute_lemonsqueezy_signature(&payload_bytes, "wrong_secret");

        let app = webhook_app(state.clone());

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

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn test_lemonsqueezy_webhook_subscription_payment_extends_license() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_id: String;
    let original_exp: i64;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        setup_lemonsqueezy_config(&conn, &org.id, &master_key);
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        original_exp = now() + (7 * 86400);
        let license = create_test_license_with_subscription(
            &conn,
            &project.id,
            &product.id,
            Some(original_exp),
            "lemonsqueezy",
            "12345", // subscription_id as string
        );
        license_id = license.id.clone();
    }

    let payload = json!({
        "meta": {
            "event_name": "subscription_payment_success"
        },
        "data": {
            "id": "invoice_ls_123",
            "attributes": {
                "subscription_id": 12345,
                "customer_id": 67890,
                "status": "paid"
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_test_secret");

    let app = webhook_app(state.clone());

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

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Verify license was extended
    let conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&conn, &license_id)
        .unwrap()
        .unwrap();
    let new_exp = license.expires_at.unwrap();
    assert!(new_exp > original_exp);
}

#[tokio::test]
async fn test_lemonsqueezy_webhook_subscription_cancelled_returns_ok() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_id: String;
    let original_exp: i64;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        setup_lemonsqueezy_config(&conn, &org.id, &master_key);
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        original_exp = now() + (30 * 86400);
        let license = create_test_license_with_subscription(
            &conn,
            &project.id,
            &product.id,
            Some(original_exp),
            "lemonsqueezy",
            "sub_ls_cancel",
        );
        license_id = license.id.clone();
    }

    let payload = json!({
        "meta": {
            "event_name": "subscription_cancelled"
        },
        "data": {
            "id": "sub_ls_cancel",
            "attributes": {
                "customer_id": 12345,
                "status": "cancelled"
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_test_secret");

    let app = webhook_app(state.clone());

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

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // License should be unchanged
    let conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&conn, &license_id)
        .unwrap()
        .unwrap();
    assert_eq!(license.expires_at, Some(original_exp));
}

#[tokio::test]
async fn test_webhook_provider_not_configured_returns_ok() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        // NO payment config set!
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&conn, &product.id, None, None);
        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    let payload = json!({
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_123",
                "payment_status": "paid",
                "metadata": {
                    "paycheck_session_id": session_id,
                    "project_id": project_id
                }
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "whsec_test_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state.clone());

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

    // Returns OK with "not configured" message (graceful degradation)
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Session should NOT be completed
    let conn = state.db.get().unwrap();
    let session = queries::get_payment_session(&conn, &session_id)
        .unwrap()
        .unwrap();
    assert!(!session.completed);
}
