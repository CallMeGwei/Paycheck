//! Webhook signature verification tests

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

    assert!(!result, "Old timestamp should be rejected (replay attack prevention)");
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

    assert!(result, "Large payload with valid signature should be accepted");
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

    assert!(result, "Large payload with valid signature should be accepted");
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

    assert!(result, "Binary payload with valid signature should be accepted");
}

#[test]
fn test_lemonsqueezy_binary_payload() {
    let client = create_lemonsqueezy_test_client();
    let payload = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
    let signature = compute_lemonsqueezy_signature(payload, "ls_test_secret");

    let result = client
        .verify_webhook_signature(payload, &signature)
        .expect("Verification should not error");

    assert!(result, "Binary payload with valid signature should be accepted");
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

    assert!(result, "Unicode payload with valid signature should be accepted");
}
