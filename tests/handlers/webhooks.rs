//! Webhook signature verification and business logic tests

#[path = "../common/mod.rs"]
mod common;

use common::{
    *, ONE_YEAR, ONE_MONTH, ONE_WEEK, ONE_DAY, UPDATES_VALID_DAYS,
};
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
fn test_stripe_old_timestamp_fails_verification() {
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
    let initial_expiration = now() + (ONE_WEEK * 86400);
    let license = create_test_license(&conn, &project.id, &product.id, Some(initial_expiration));

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
    assert_eq!(
        status1,
        StatusCode::OK,
        "first renewal request should return OK status"
    );

    // Check license was extended (product has ONE_YEAR day license_exp_days)
    let updated_license = queries::get_license_by_id(&conn, &license.id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    let first_expiration = updated_license.expires_at.expect("license should have expiration timestamp");
    assert!(
        first_expiration > initial_expiration,
        "license expiration should be extended after first renewal"
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
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    let final_expiration = final_license.expires_at.expect("license should have expiration timestamp");

    assert_eq!(
        first_expiration, final_expiration,
        "license expiration should not change on replay attack"
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

    let initial_expiration = now() + (ONE_WEEK * 86400);
    let license = create_test_license(&conn, &project.id, &product.id, Some(initial_expiration));

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
    assert_eq!(
        status1,
        StatusCode::OK,
        "first renewal event should return OK status"
    );

    // Second renewal event (different event ID - legitimate new renewal)
    let (status2, msg2) = process_renewal(
        &conn,
        "test_provider",
        &product,
        &license.id,
        subscription_id,
        Some("invoice_002"), // Different event ID
    );
    assert_eq!(
        status2,
        StatusCode::OK,
        "second renewal with different event ID should return OK status"
    );
    assert!(
        !msg2.contains("Already processed"),
        "different event ID should be processed as new renewal, not rejected as duplicate"
    );
}

// ============ Checkout Business Logic Tests ============

#[test]
fn test_checkout_creates_license_and_device() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

    // Create payment session (no device info - that's at activation time)
    let session = create_test_payment_session(&conn, &product.id, Some("cust_test"));

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
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );

    assert_eq!(
        status,
        StatusCode::OK,
        "checkout process should return OK status"
    );
    assert_eq!(msg, "OK", "checkout process should return OK message");

    // Verify license was created
    let updated_session = queries::get_payment_session(&conn, &session.id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    assert!(
        updated_session.completed,
        "payment session should be marked as completed"
    );
    assert!(
        updated_session.license_id.is_some(),
        "payment session should have associated license ID"
    );

    // Verify license has correct metadata
    let license_id = updated_session.license_id.unwrap();
    let license = queries::get_license_by_id(&conn, &license_id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    assert_eq!(
        license.payment_provider.as_deref(),
        Some("stripe"),
        "license payment provider should be stripe"
    );
    assert_eq!(
        license.payment_provider_subscription_id.as_deref(),
        Some("sub_123"),
        "license should have correct subscription ID"
    );
    assert_eq!(
        license.payment_provider_order_id.as_deref(),
        Some("cs_test_123"),
        "license should have correct order ID"
    );

    // Device creation is deferred to activation time (/redeem/key)
    // Verify NO device was created during checkout
    let devices = queries::list_devices_for_license(&conn, &license_id)
        .expect("database query for devices should succeed");
    assert_eq!(
        devices.len(),
        0,
        "no device should be created at checkout - activation creates the device"
    );
}

#[test]
fn test_checkout_concurrent_webhooks_create_only_one_license() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

    let session = create_test_payment_session(&conn, &product.id, None);

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
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );
    assert_eq!(
        status1,
        StatusCode::OK,
        "first checkout call should return OK status"
    );
    assert_eq!(
        msg1, "OK",
        "first checkout call should return OK message"
    );

    // Second call with same session should be rejected
    let (status2, msg2) = process_checkout(
        &mut conn,
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );
    assert_eq!(
        status2,
        StatusCode::OK,
        "duplicate checkout call should return OK status (idempotent)"
    );
    assert_eq!(
        msg2, "Already processed",
        "duplicate checkout call should indicate already processed"
    );

    // Verify only one license exists for the session
    let updated_session = queries::get_payment_session(&conn, &session.id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    let license_id = updated_session.license_id.expect("payment session should have license ID");

    // Device creation is deferred to activation time (/redeem/key)
    // Verify NO device was created during checkout
    let devices = queries::list_devices_for_license(&conn, &license_id)
        .expect("database query for devices should succeed");
    assert_eq!(
        devices.len(),
        0,
        "no device should be created at checkout - device is created at activation time"
    );
}

#[test]
fn test_checkout_creates_license_with_product_expirations() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

    // Create product with specific expirations
    let input = CreateProduct {
        name: "Pro Plan".to_string(),
        tier: "pro".to_string(),
        license_exp_days: Some(ONE_MONTH as i32),
        updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
        activation_limit: 5,
        device_limit: 3,
        features: vec![],
    };
    let product = queries::create_product(&conn, &project.id, &input)
        .expect("product creation should succeed");

    let session = create_test_payment_session(&conn, &product.id, None);

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
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "checkout process should return OK status"
    );

    let updated_session = queries::get_payment_session(&conn, &session.id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    let license = queries::get_license_by_id(&conn, &updated_session.license_id.unwrap())
        .expect("database query for license should succeed")
        .expect("license should exist in database");

    // License should expire in ~ONE_MONTH days
    let license_exp = license.expires_at.expect("license should have expiration timestamp");
    assert!(
        license_exp >= before + (ONE_MONTH * 86400) - 5,
        "license expiration should be at least {} days from now",
        ONE_MONTH
    );
    assert!(
        license_exp <= before + (ONE_MONTH * 86400) + 5,
        "license expiration should be at most {} days from now",
        ONE_MONTH
    );

    // Updates should expire in ~UPDATES_VALID_DAYS days
    let updates_exp = license.updates_expires_at.expect("license should have updates expiration timestamp");
    assert!(
        updates_exp >= before + (UPDATES_VALID_DAYS * 86400) - 5,
        "updates expiration should be at least {} days from now",
        UPDATES_VALID_DAYS
    );
    assert!(
        updates_exp <= before + (UPDATES_VALID_DAYS * 86400) + 5,
        "updates expiration should be at most {} days from now",
        UPDATES_VALID_DAYS
    );
}

#[test]
fn test_checkout_perpetual_license() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

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
    let product = queries::create_product(&conn, &project.id, &input)
        .expect("product creation should succeed");

    let session = create_test_payment_session(&conn, &product.id, None);

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
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "checkout process should return OK status for perpetual license"
    );

    let updated_session = queries::get_payment_session(&conn, &session.id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    let license = queries::get_license_by_id(&conn, &updated_session.license_id.unwrap())
        .expect("database query for license should succeed")
        .expect("license should exist in database");

    assert!(
        license.expires_at.is_none(),
        "perpetual license should have no expiration"
    );
    assert!(
        license.updates_expires_at.is_none(),
        "perpetual license should have no updates expiration"
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
    let initial_exp = now() + (ONE_WEEK * 86400); // 7 days from now
    let license = create_test_license(&conn, &project.id, &product.id, Some(initial_exp));

    let (status, _) = process_renewal(
        &conn,
        "stripe",
        &product,
        &license.id,
        "sub_123",
        Some("invoice_001"),
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "renewal process should return OK status"
    );

    let updated = queries::get_license_by_id(&conn, &license.id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    let new_exp = updated.expires_at.expect("license should have expiration timestamp");

    // Product has ONE_YEAR day license_exp_days, so new exp should be ~ONE_YEAR days from now
    let expected_min = now() + (ONE_YEAR * 86400) - 10;
    let expected_max = now() + (ONE_YEAR * 86400) + 10;
    assert!(
        new_exp >= expected_min && new_exp <= expected_max,
        "license should be extended by product expiration ({} days), got {} days",
        ONE_YEAR,
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

    let license = create_test_license(&conn, &project.id, &product.id, Some(now() + (ONE_DAY * 86400)));

    // First call without event_id
    let (status1, msg1) = process_renewal(
        &conn,
        "stripe",
        &product,
        &license.id,
        "sub_123",
        None, // No event_id - no replay prevention
    );
    assert_eq!(
        status1,
        StatusCode::OK,
        "first renewal without event_id should return OK status"
    );
    assert_eq!(
        msg1, "OK",
        "first renewal without event_id should return OK message"
    );

    // Second call also processes (no replay prevention)
    let (status2, msg2) = process_renewal(&conn, "stripe", &product, &license.id, "sub_123", None);
    assert_eq!(
        status2,
        StatusCode::OK,
        "second renewal without event_id should return OK status (no replay prevention)"
    );
    assert_eq!(
        msg2, "OK",
        "second renewal without event_id should return OK message (no replay prevention)"
    );
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

    let original_exp = now() + (ONE_MONTH * 86400);
    let license = create_test_license(&conn, &project.id, &product.id, Some(original_exp));

    let (status, msg) = process_cancellation("stripe", &license.id, license.expires_at, "sub_123");
    assert_eq!(
        status,
        StatusCode::OK,
        "cancellation process should return OK status"
    );
    assert_eq!(
        msg, "OK",
        "cancellation process should return OK message"
    );

    // Verify license was NOT modified
    let unchanged = queries::get_license_by_id(&conn, &license.id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    assert_eq!(
        unchanged.expires_at,
        Some(original_exp),
        "license expiration should remain unchanged after cancellation"
    );
    assert!(
        !unchanged.revoked,
        "license should not be revoked after cancellation (expires naturally)"
    );
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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "Stripe checkout webhook should return OK status"
    );

    // Verify license was created
    let conn = state.db.get().unwrap();
    let session = queries::get_payment_session(&conn, &session_id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    assert!(
        session.completed,
        "payment session should be marked as completed after webhook"
    );
    assert!(
        session.license_id.is_some(),
        "payment session should have associated license ID after webhook"
    );

    let license = queries::get_license_by_id(&conn, &session.license_id.unwrap())
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    assert_eq!(
        license.payment_provider.as_deref(),
        Some("stripe"),
        "license payment provider should be stripe"
    );
    assert_eq!(
        license.payment_provider_subscription_id.as_deref(),
        Some("sub_test_123"),
        "license should have correct subscription ID from webhook"
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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "missing stripe-signature header should return BAD_REQUEST"
    );
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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNAUTHORIZED,
        "invalid webhook signature should return UNAUTHORIZED"
    );
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
        let session = create_test_payment_session(&conn, &product.id, None);
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
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "unpaid checkout webhook should return OK (event ignored)"
    );

    // Session should NOT be completed
    let conn = state.db.get().unwrap();
    let session = queries::get_payment_session(&conn, &session_id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    assert!(
        !session.completed,
        "payment session should not be completed for unpaid checkout"
    );
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
        original_exp = now() + (ONE_WEEK * 86400);
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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "invoice.paid webhook should return OK status"
    );

    // Verify license was extended
    let conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&conn, &license_id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    let new_exp = license.expires_at.expect("license should have expiration timestamp");
    assert!(
        new_exp > original_exp,
        "license should be extended from {} to {} after invoice.paid webhook",
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

        original_exp = now() + (ONE_MONTH * 86400);
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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "subscription.deleted webhook should return OK status"
    );

    // License should be unchanged (expires naturally)
    let conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&conn, &license_id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    assert_eq!(
        license.expires_at,
        Some(original_exp),
        "license expiration should remain unchanged after subscription.deleted webhook"
    );
    assert!(
        !license.revoked,
        "license should not be revoked after subscription.deleted webhook"
    );
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
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "unknown webhook event type should return OK (event ignored)"
    );
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

        let session = create_test_payment_session(&conn, &product.id, None);

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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "LemonSqueezy order_created webhook should return OK status"
    );

    // Verify license was created
    let conn = state.db.get().unwrap();
    let session = queries::get_payment_session(&conn, &session_id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    assert!(
        session.completed,
        "payment session should be marked as completed after webhook"
    );
    assert!(
        session.license_id.is_some(),
        "payment session should have associated license ID after webhook"
    );

    let license = queries::get_license_by_id(&conn, &session.license_id.unwrap())
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    assert_eq!(
        license.payment_provider.as_deref(),
        Some("lemonsqueezy"),
        "license payment provider should be lemonsqueezy"
    );
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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "missing x-signature header should return BAD_REQUEST"
    );
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
        let session = create_test_payment_session(&conn, &product.id, None);

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

        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid LemonSqueezy webhook signature should return UNAUTHORIZED"
        );
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

        original_exp = now() + (ONE_WEEK * 86400);
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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "subscription_payment_success webhook should return OK status"
    );

    // Verify license was extended
    let conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&conn, &license_id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    let new_exp = license.expires_at.expect("license should have expiration timestamp");
    assert!(
        new_exp > original_exp,
        "license should be extended after subscription_payment_success webhook"
    );
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

        original_exp = now() + (ONE_MONTH * 86400);
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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "subscription_cancelled webhook should return OK status"
    );

    // License should be unchanged
    let conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&conn, &license_id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    assert_eq!(
        license.expires_at,
        Some(original_exp),
        "license expiration should remain unchanged after subscription_cancelled webhook"
    );
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
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "webhook should return OK even when payment provider is not configured"
    );

    // Session should NOT be completed
    let conn = state.db.get().unwrap();
    let session = queries::get_payment_session(&conn, &session_id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    assert!(
        !session.completed,
        "payment session should not be completed when provider is not configured"
    );
}

// ============ Webhook Security Tests ============
//
// These tests focus on replay attack prevention, timestamp validation,
// payload manipulation detection, and edge cases in webhook handling.

mod webhook_security {
    use super::*;

    // ============ Stripe Replay Prevention Tests ============

    /// Test that Stripe checkout webhook with the same session creates only one license.
    /// Uses atomic session claiming to prevent race conditions.
    #[tokio::test]
    async fn test_stripe_webhook_same_event_id_processed_once() {
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
                    }
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let timestamp = current_timestamp();
        let signature = compute_stripe_signature(&payload_bytes, "whsec_test_secret", &timestamp);
        let signature_header = format!("t={},v1={}", timestamp, signature);

        let app = webhook_app(state.clone());

        // First request - should succeed
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", &signature_header)
                    .body(Body::from(payload_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response1.status(),
            axum::http::StatusCode::OK,
            "first webhook request should return OK status"
        );

        // Second request with same payload - should be idempotent
        let response2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", &signature_header)
                    .body(Body::from(payload_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response2.status(),
            axum::http::StatusCode::OK,
            "replay webhook request should return OK status (idempotent)"
        );

        // Verify only one license was created
        let conn = state.db.get().unwrap();
        let session = queries::get_payment_session(&conn, &session_id)
            .expect("database query for payment session should succeed")
            .expect("payment session should exist in database");
        assert!(
            session.completed,
            "payment session should be marked as completed"
        );

        let license_id = session.license_id.expect("payment session should have license ID");
        let licenses = queries::list_licenses_for_project(&conn, &project_id)
            .expect("database query for licenses should succeed");
        assert_eq!(
            licenses.len(),
            1,
            "replay should not create duplicate license"
        );
        assert_eq!(
            licenses[0].license.id, license_id,
            "license ID should match session's license ID"
        );
    }

    /// Test that replaying a Stripe checkout webhook does not create duplicate licenses.
    #[tokio::test]
    async fn test_stripe_webhook_replay_does_not_create_duplicate_license() {
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
            let session = create_test_payment_session(&conn, &product.id, None);
            session_id = session.id.clone();
            project_id = project.id.clone();
        }

        // Helper to send webhook
        let send_webhook = |app: Router, bytes: Vec<u8>, sig: String| async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", sig)
                    .body(Body::from(bytes))
                    .unwrap(),
            )
            .await
            .unwrap()
        };

        let payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_replay",
                    "payment_status": "paid",
                    "customer_email": "replay@test.com",
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

        // Send multiple times
        let app = webhook_app(state.clone());
        let _ = send_webhook(app.clone(), payload_bytes.clone(), signature_header.clone()).await;
        let _ = send_webhook(app.clone(), payload_bytes.clone(), signature_header.clone()).await;
        let _ = send_webhook(app, payload_bytes, signature_header).await;

        // Verify only one license
        let conn = state.db.get().unwrap();
        let licenses = queries::list_licenses_for_project(&conn, &project_id)
            .expect("database query for licenses should succeed");
        assert_eq!(
            licenses.len(),
            1,
            "multiple replays should still result in only 1 license"
        );
    }

    /// Test that Stripe invoice.paid replay prevention works via event_id tracking.
    #[tokio::test]
    async fn test_stripe_invoice_paid_replay_prevented() {
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

            original_exp = now() + (ONE_WEEK * 86400);
            let license = create_test_license_with_subscription(
                &conn,
                &project.id,
                &product.id,
                Some(original_exp),
                "stripe",
                "sub_replay_test",
            );
            license_id = license.id.clone();
        }

        // Same invoice ID sent multiple times (replay attack)
        let payload = json!({
            "type": "invoice.paid",
            "data": {
                "object": {
                    "id": "in_same_invoice_id",  // Same ID for replay
                    "subscription": "sub_replay_test",
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

        // First request extends license
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", &signature_header)
                    .body(Body::from(payload_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response1.status(),
            axum::http::StatusCode::OK,
            "first invoice.paid webhook should return OK status"
        );

        let conn = state.db.get().unwrap();
        let license_after_first = queries::get_license_by_id(&conn, &license_id)
            .expect("database query for license should succeed")
            .expect("license should exist in database");
        let first_exp = license_after_first.expires_at.expect("license should have expiration timestamp");
        assert!(
            first_exp > original_exp,
            "first renewal should extend license expiration"
        );

        // Second request with same invoice ID should be idempotent
        let response2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", &signature_header)
                    .body(Body::from(payload_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response2.status(),
            axum::http::StatusCode::OK,
            "replay invoice.paid webhook should return OK status (idempotent)"
        );

        // Verify expiration was not extended again
        let license_after_second = queries::get_license_by_id(&conn, &license_id)
            .expect("database query for license should succeed")
            .expect("license should exist in database");
        assert_eq!(
            license_after_second.expires_at.expect("license should have expiration timestamp"),
            first_exp,
            "replay should not extend license expiration again"
        );
    }

    // ============ LemonSqueezy Replay Prevention Tests ============

    /// Test that LemonSqueezy order_created webhook replay is prevented via session claiming.
    #[tokio::test]
    async fn test_lemonsqueezy_webhook_same_event_processed_once() {
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
            let session = create_test_payment_session(&conn, &product.id, None);
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
                "id": "order_ls_replay_test",
                "attributes": {
                    "status": "paid",
                    "customer_id": 12345
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_test_secret");

        let app = webhook_app(state.clone());

        // First request
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/lemonsqueezy")
                    .header("content-type", "application/json")
                    .header("x-signature", &signature)
                    .body(Body::from(payload_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response1.status(),
            axum::http::StatusCode::OK,
            "first LemonSqueezy order_created webhook should return OK status"
        );

        // Replay request
        let response2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/lemonsqueezy")
                    .header("content-type", "application/json")
                    .header("x-signature", &signature)
                    .body(Body::from(payload_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response2.status(),
            axum::http::StatusCode::OK,
            "replay LemonSqueezy webhook should return OK status (idempotent)"
        );

        // Verify only one license
        let conn = state.db.get().unwrap();
        let licenses = queries::list_licenses_for_project(&conn, &project_id)
            .expect("database query for licenses should succeed");
        assert_eq!(
            licenses.len(),
            1,
            "replay should not create duplicate license"
        );
    }

    /// Test that LemonSqueezy subscription_payment_success replay is prevented.
    #[tokio::test]
    async fn test_lemonsqueezy_webhook_replay_does_not_duplicate() {
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

            original_exp = now() + (ONE_WEEK * 86400);
            let license = create_test_license_with_subscription(
                &conn,
                &project.id,
                &product.id,
                Some(original_exp),
                "lemonsqueezy",
                "99999",
            );
            license_id = license.id.clone();
        }

        // Same invoice ID for replay attack
        let payload = json!({
            "meta": {
                "event_name": "subscription_payment_success"
            },
            "data": {
                "id": "ls_invoice_same_id",  // Same ID
                "attributes": {
                    "subscription_id": 99999,
                    "customer_id": 12345,  // Required field
                    "status": "paid"
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_test_secret");

        let app = webhook_app(state.clone());

        // First request
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/lemonsqueezy")
                    .header("content-type", "application/json")
                    .header("x-signature", &signature)
                    .body(Body::from(payload_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let conn = state.db.get().unwrap();
        let license_after_first = queries::get_license_by_id(&conn, &license_id)
            .expect("database query for license should succeed")
            .expect("license should exist in database");
        let first_exp = license_after_first.expires_at.expect("license should have expiration timestamp");
        assert!(
            first_exp > original_exp,
            "first renewal should extend license expiration"
        );

        // Replay
        let _ = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/lemonsqueezy")
                    .header("content-type", "application/json")
                    .header("x-signature", &signature)
                    .body(Body::from(payload_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        let license_after_replay = queries::get_license_by_id(&conn, &license_id)
            .expect("database query for license should succeed")
            .expect("license should exist in database");
        assert_eq!(
            license_after_replay.expires_at.expect("license should have expiration timestamp"),
            first_exp,
            "replay should not extend license expiration"
        );
    }

    // ============ Timestamp Validation Tests ============

    /// Test that Stripe webhook with timestamp > 5 minutes old is rejected.
    /// Timestamp validation happens during signature verification.
    #[tokio::test]
    async fn test_stripe_webhook_old_timestamp_returns_unauthorized() {
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
            let session = create_test_payment_session(&conn, &product.id, None);
            session_id = session.id.clone();
            project_id = project.id.clone();
        }

        // Valid payload that would normally succeed
        let payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_old_ts",
                    "payment_status": "paid",
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        // Timestamp 10 minutes ago (beyond 5-minute tolerance)
        let old_timestamp = (chrono::Utc::now().timestamp() - 600).to_string();
        let signature =
            compute_stripe_signature(&payload_bytes, "whsec_test_secret", &old_timestamp);
        let signature_header = format!("t={},v1={}", old_timestamp, signature);

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

        // Old timestamp causes signature verification to fail (returns false)
        // which results in UNAUTHORIZED
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "Old timestamp should cause signature rejection"
        );
    }

    /// Test that Stripe webhook with future timestamp is rejected.
    /// Clock skew tolerance is 60 seconds - timestamps more than 60s in the future are rejected.
    #[tokio::test]
    async fn test_stripe_webhook_future_timestamp_returns_unauthorized() {
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
            let session = create_test_payment_session(&conn, &product.id, None);
            session_id = session.id.clone();
            project_id = project.id.clone();
        }

        // Valid payload that would normally succeed
        let payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_future_ts",
                    "payment_status": "paid",
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        // Timestamp 5 minutes in the future (beyond 60-second clock skew tolerance)
        let future_timestamp = (chrono::Utc::now().timestamp() + 300).to_string();
        let signature =
            compute_stripe_signature(&payload_bytes, "whsec_test_secret", &future_timestamp);
        let signature_header = format!("t={},v1={}", future_timestamp, signature);

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

        // Future timestamp causes signature verification to fail (returns false)
        // which results in UNAUTHORIZED
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "Future timestamp should cause signature rejection"
        );
    }

    // ============ Payload Manipulation Tests ============

    /// Test that modifying the payment amount in payload causes signature failure.
    #[tokio::test]
    async fn test_stripe_webhook_modified_amount_returns_unauthorized() {
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
            let session = create_test_payment_session(&conn, &product.id, None);
            session_id = session.id.clone();
            project_id = project.id.clone();
        }

        // Original payload with $99 amount
        let original_payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "payment_status": "paid",
                    "amount_total": 9900,  // $99.00
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let original_bytes = serde_json::to_vec(&original_payload).unwrap();
        let timestamp = current_timestamp();
        let signature = compute_stripe_signature(&original_bytes, "whsec_test_secret", &timestamp);
        let signature_header = format!("t={},v1={}", timestamp, signature);

        // Attacker modifies the amount to $0
        let modified_payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "payment_status": "paid",
                    "amount_total": 0,  // Modified to $0
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let modified_bytes = serde_json::to_vec(&modified_payload).unwrap();

        let app = webhook_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", signature_header)
                    .body(Body::from(modified_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "Modified payload should be rejected"
        );
    }

    /// Test that modifying customer email in payload causes signature failure.
    #[tokio::test]
    async fn test_stripe_webhook_modified_customer_email_returns_unauthorized() {
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
            let session = create_test_payment_session(&conn, &product.id, None);
            session_id = session.id.clone();
            project_id = project.id.clone();
        }

        // Sign with original email
        let original_payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "payment_status": "paid",
                    "customer_email": "legitimate@buyer.com",
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let original_bytes = serde_json::to_vec(&original_payload).unwrap();
        let timestamp = current_timestamp();
        let signature = compute_stripe_signature(&original_bytes, "whsec_test_secret", &timestamp);
        let signature_header = format!("t={},v1={}", timestamp, signature);

        // Attacker tries to substitute their email
        let modified_payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "payment_status": "paid",
                    "customer_email": "attacker@evil.com",  // Modified email
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let modified_bytes = serde_json::to_vec(&modified_payload).unwrap();

        let app = webhook_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", signature_header)
                    .body(Body::from(modified_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "Modified email should be rejected"
        );
    }

    // ============ Edge Cases ============

    /// Test that webhook for non-existent product returns OK (graceful handling).
    #[tokio::test]
    async fn test_webhook_with_unknown_product_id_ignored() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            setup_stripe_config(&conn, &org.id, &master_key);
            // Project exists but no product or session
            let _project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        }

        let payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_unknown",
                    "payment_status": "paid",
                    "metadata": {
                        "paycheck_session_id": "non_existent_session_id",
                        "project_id": "non_existent_project_id"
                    }
                }
            }
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

        // Should return OK (graceful degradation) rather than crashing
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Unknown product should be handled gracefully"
        );
    }

    /// Test that webhook for unknown subscription is handled gracefully.
    #[tokio::test]
    async fn test_webhook_with_unknown_subscription_ignored() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            setup_stripe_config(&conn, &org.id, &master_key);
        }

        let payload = json!({
            "type": "invoice.paid",
            "data": {
                "object": {
                    "id": "in_unknown_invoice",
                    "subscription": "sub_does_not_exist",
                    "billing_reason": "subscription_cycle",
                    "status": "paid"
                }
            }
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

        // Should return OK with "not found" message rather than error
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "unknown subscription webhook should return OK (handled gracefully)"
        );
    }

    /// Test that concurrent webhooks for the same order create only one license.
    /// This simulates Stripe's retry behavior where multiple webhooks might arrive
    /// simultaneously.
    #[tokio::test]
    async fn test_concurrent_webhooks_same_order_create_one_license() {
        use std::sync::Arc;
        use tokio::sync::Barrier;

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
            let session = create_test_payment_session(&conn, &product.id, None);
            session_id = session.id.clone();
            project_id = project.id.clone();
        }

        let payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_concurrent_test",
                    "payment_status": "paid",
                    "customer_email": "concurrent@test.com",
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

        // Use a barrier to synchronize concurrent requests
        let barrier = Arc::new(Barrier::new(5));
        let state = Arc::new(state);
        let payload_bytes = Arc::new(payload_bytes);
        let signature_header = Arc::new(signature_header);

        // Spawn 5 concurrent webhook requests
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let barrier = barrier.clone();
                let state = state.clone();
                let payload_bytes = payload_bytes.clone();
                let signature_header = signature_header.clone();

                tokio::spawn(async move {
                    // Wait for all tasks to be ready
                    barrier.wait().await;

                    let app = webhook_app((*state).clone());
                    app.oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/webhook/stripe")
                            .header("content-type", "application/json")
                            .header("stripe-signature", signature_header.as_str())
                            .body(Body::from(payload_bytes.as_ref().clone()))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
                })
            })
            .collect();

        // Wait for all requests to complete
        for handle in handles {
            let response = handle.await.unwrap();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::OK,
                "all concurrent webhook requests should return OK"
            );
        }

        // Verify only ONE license was created despite concurrent requests
        let conn = state.db.get().unwrap();
        let licenses = queries::list_licenses_for_project(&conn, &project_id)
            .expect("database query for licenses should succeed");
        assert_eq!(
            licenses.len(),
            1,
            "concurrent webhooks should create exactly 1 license, found {}",
            licenses.len()
        );
    }

    /// Test that LemonSqueezy webhook for unknown subscription returns OK.
    /// When a subscription is not found, the webhook returns OK with a "not found" message
    /// rather than an error (graceful handling for webhooks).
    #[tokio::test]
    async fn test_lemonsqueezy_unknown_subscription_returns_ok_gracefully() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            setup_lemonsqueezy_config(&conn, &org.id, &master_key);
            // Need a project for the org so the config can be looked up
            let _project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        }

        // Include all required fields for the payload
        let payload = json!({
            "meta": {
                "event_name": "subscription_payment_success"
            },
            "data": {
                "id": "ls_invoice_unknown",
                "attributes": {
                    "subscription_id": 99999999,  // Does not exist
                    "customer_id": 12345,         // Required field
                    "status": "paid"
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_test_secret");

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

        // Should return OK, not an error (subscription not found is handled gracefully)
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "unknown LemonSqueezy subscription webhook should return OK (handled gracefully)"
        );
    }
}
