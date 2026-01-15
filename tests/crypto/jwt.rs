//! JWT signing and validation tests

#[path = "../common/mod.rs"]
mod common;

use common::{LICENSE_VALID_DAYS, ONE_DAY, ONE_YEAR, UPDATES_VALID_DAYS};
use paycheck::jwt::{self, LicenseClaims};

/// Seconds per day constant for timestamp calculations
const SECONDS_PER_DAY: i64 = 86400;

fn create_test_claims() -> LicenseClaims {
    let now = chrono::Utc::now().timestamp();
    LicenseClaims {
        license_exp: Some(now + SECONDS_PER_DAY * LICENSE_VALID_DAYS),
        updates_exp: Some(now + SECONDS_PER_DAY * UPDATES_VALID_DAYS),
        tier: "pro".to_string(),
        features: vec!["export".to_string(), "api".to_string()],
        device_id: "device-123".to_string(),
        device_type: "uuid".to_string(),
        product_id: "product-abc".to_string(),
    }
}

// ============ Keypair Generation Tests ============

#[test]
fn test_keypair_generation_produces_valid_lengths() {
    let (private_key, public_key) = jwt::generate_keypair();

    assert_eq!(
        private_key.len(),
        32,
        "Ed25519 private key should be 32 bytes"
    );
    // Base64 of 32 bytes = 44 characters (with padding)
    assert!(!public_key.is_empty(), "Public key should not be empty");
}

#[test]
fn test_keypair_generation_is_unique() {
    let (private1, public1) = jwt::generate_keypair();
    let (private2, public2) = jwt::generate_keypair();

    assert_ne!(private1, private2, "Private keys should be unique");
    assert_ne!(public1, public2, "Public keys should be unique");
}

// ============ Sign and Verify Tests ============

#[test]
fn test_sign_and_verify_roundtrip() {
    let (private_key, public_key) = jwt::generate_keypair();
    let claims = create_test_claims();

    let token = jwt::sign_claims(&claims, &private_key, "license-id", "myapp.com", "jti-123")
        .expect("Signing should succeed");

    let verified = jwt::verify_token(&token, &public_key).expect("Verification should succeed");

    assert_eq!(
        verified.custom.tier, "pro",
        "Verified token should preserve tier claim"
    );
    assert_eq!(
        verified.custom.device_id, "device-123",
        "Verified token should preserve device_id claim"
    );
    assert_eq!(
        verified.custom.product_id, "product-abc",
        "Verified token should preserve product_id claim"
    );
    assert_eq!(
        verified.custom.features,
        vec!["export", "api"],
        "Verified token should preserve features array"
    );
}

#[test]
fn test_sign_preserves_standard_claims() {
    let (private_key, public_key) = jwt::generate_keypair();
    let claims = create_test_claims();

    let token = jwt::sign_claims(&claims, &private_key, "my-subject", "my-audience", "my-jti")
        .expect("Signing should succeed");

    let verified = jwt::verify_token(&token, &public_key).expect("Verification should succeed");

    assert_eq!(
        verified.subject,
        Some("my-subject".to_string()),
        "Verified token should preserve subject claim"
    );
    assert!(
        verified.audiences.is_some(),
        "Verified token should have audiences set"
    );
    assert_eq!(
        verified.jwt_id,
        Some("my-jti".to_string()),
        "Verified token should preserve JTI claim"
    );
    assert_eq!(
        verified.issuer,
        Some("paycheck".to_string()),
        "Verified token should have 'paycheck' as issuer"
    );
}

#[test]
fn test_verify_with_wrong_key_fails() {
    let (private_key, _public_key) = jwt::generate_keypair();
    let (_, wrong_public_key) = jwt::generate_keypair(); // Different key pair
    let claims = create_test_claims();

    let token = jwt::sign_claims(&claims, &private_key, "license-id", "myapp.com", "jti-123")
        .expect("Signing should succeed");

    let result = jwt::verify_token(&token, &wrong_public_key);
    assert!(result.is_err(), "Verification with wrong key should fail");
}

#[test]
fn test_verify_tampered_token_fails() {
    let (private_key, public_key) = jwt::generate_keypair();
    let claims = create_test_claims();

    let token = jwt::sign_claims(&claims, &private_key, "license-id", "myapp.com", "jti-123")
        .expect("Signing should succeed");

    // Tamper with the token by modifying a character in the payload (middle part)
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "JWT should have three parts (header.payload.signature)"
    );

    // Modify the payload slightly
    let mut payload_chars: Vec<char> = parts[1].chars().collect();
    if let Some(c) = payload_chars.get_mut(10) {
        *c = if *c == 'a' { 'b' } else { 'a' };
    }
    let tampered_payload: String = payload_chars.into_iter().collect();
    let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

    let result = jwt::verify_token(&tampered_token, &public_key);
    assert!(
        result.is_err(),
        "Verification of tampered token should fail"
    );
}

#[test]
fn test_verify_truncated_token_fails() {
    let (private_key, public_key) = jwt::generate_keypair();
    let claims = create_test_claims();

    let token = jwt::sign_claims(&claims, &private_key, "license-id", "myapp.com", "jti-123")
        .expect("Signing should succeed");

    // Remove the last 10 characters
    let truncated = &token[..token.len() - 10];

    let result = jwt::verify_token(truncated, &public_key);
    assert!(
        result.is_err(),
        "Verification of truncated token should fail"
    );
}

// ============ Decode Unverified Tests ============

#[test]
fn test_decode_unverified_extracts_claims() {
    let (private_key, _) = jwt::generate_keypair();
    let claims = create_test_claims();

    let token = jwt::sign_claims(&claims, &private_key, "license-id", "myapp.com", "jti-123")
        .expect("Signing should succeed");

    let decoded = jwt::decode_unverified(&token).expect("Decode should succeed");

    assert_eq!(
        decoded.product_id, "product-abc",
        "Decoded token should have correct product_id"
    );
    assert_eq!(decoded.tier, "pro", "Decoded token should have correct tier");
}

#[test]
fn test_decode_unverified_invalid_format() {
    let result = jwt::decode_unverified("not-a-jwt");
    assert!(
        result.is_err(),
        "Decoding non-JWT string should return error"
    );
}

#[test]
fn test_decode_unverified_empty_string() {
    let result = jwt::decode_unverified("");
    assert!(result.is_err(), "Decoding empty string should return error");
}

#[test]
fn test_decode_unverified_missing_parts() {
    let result = jwt::decode_unverified("header.payload"); // Missing signature
    assert!(
        result.is_err(),
        "Decoding JWT with missing signature part should return error"
    );
}

// ============ Invalid Key Tests ============

#[test]
fn test_sign_with_short_key_fails() {
    let short_key = vec![0u8; 16]; // Only 16 bytes, need 32
    let claims = create_test_claims();

    let result = jwt::sign_claims(&claims, &short_key, "license-id", "myapp.com", "jti-123");
    assert!(
        result.is_err(),
        "Signing with 16-byte key should fail (Ed25519 requires 32 bytes)"
    );
}

#[test]
fn test_sign_with_long_key_fails() {
    let long_key = vec![0u8; 64]; // 64 bytes, need 32
    let claims = create_test_claims();

    let result = jwt::sign_claims(&claims, &long_key, "license-id", "myapp.com", "jti-123");
    assert!(
        result.is_err(),
        "Signing with 64-byte key should fail (Ed25519 requires exactly 32 bytes)"
    );
}

#[test]
fn test_verify_with_invalid_public_key_format() {
    let (private_key, _) = jwt::generate_keypair();
    let claims = create_test_claims();

    let token = jwt::sign_claims(&claims, &private_key, "license-id", "myapp.com", "jti-123")
        .expect("Signing should succeed");

    // Invalid base64
    let result = jwt::verify_token(&token, "not-valid-base64!!!");
    assert!(
        result.is_err(),
        "Verification with invalid base64 public key should fail"
    );
}

#[test]
fn test_verify_with_short_public_key() {
    let (private_key, _) = jwt::generate_keypair();
    let claims = create_test_claims();

    let token = jwt::sign_claims(&claims, &private_key, "license-id", "myapp.com", "jti-123")
        .expect("Signing should succeed");

    // Valid base64 but wrong length
    let short_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 16]);
    let result = jwt::verify_token(&token, &short_key);
    assert!(
        result.is_err(),
        "Verification with 16-byte public key should fail (Ed25519 requires 32 bytes)"
    );
}

// ============ Claims Logic Tests ============

#[test]
fn test_is_license_expired_future() {
    let now = chrono::Utc::now().timestamp();
    let claims = LicenseClaims {
        license_exp: Some(now + SECONDS_PER_DAY * ONE_DAY), // Expires tomorrow
        updates_exp: None,
        tier: "pro".to_string(),
        features: vec![],
        device_id: "".to_string(),
        device_type: "uuid".to_string(),
        product_id: "".to_string(),
    };

    assert!(
        !claims.is_license_expired(now),
        "License expiring tomorrow should not be expired now"
    );
}

#[test]
fn test_is_license_expired_past() {
    let now = chrono::Utc::now().timestamp();
    let claims = LicenseClaims {
        license_exp: Some(now - SECONDS_PER_DAY * ONE_DAY), // Expired yesterday
        updates_exp: None,
        tier: "pro".to_string(),
        features: vec![],
        device_id: "".to_string(),
        device_type: "uuid".to_string(),
        product_id: "".to_string(),
    };

    assert!(
        claims.is_license_expired(now),
        "License that expired yesterday should be expired now"
    );
}

#[test]
fn test_is_license_expired_perpetual() {
    let now = chrono::Utc::now().timestamp();
    let claims = LicenseClaims {
        license_exp: None, // Perpetual license
        updates_exp: None,
        tier: "pro".to_string(),
        features: vec![],
        device_id: "".to_string(),
        device_type: "uuid".to_string(),
        product_id: "".to_string(),
    };

    assert!(
        !claims.is_license_expired(now),
        "Perpetual license (None expiration) should never be expired"
    );
}

#[test]
fn test_covers_version_with_updates_exp() {
    let now = chrono::Utc::now().timestamp();
    let claims = LicenseClaims {
        license_exp: None,
        updates_exp: Some(now + SECONDS_PER_DAY * ONE_DAY), // Updates expire tomorrow
        tier: "pro".to_string(),
        features: vec![],
        device_id: "".to_string(),
        device_type: "uuid".to_string(),
        product_id: "".to_string(),
    };

    // Version released before updates expiration
    assert!(
        claims.covers_version(now - SECONDS_PER_DAY * ONE_DAY),
        "Version released before updates_exp should be covered"
    );
    // Version released after updates expiration
    assert!(
        !claims.covers_version(now + SECONDS_PER_DAY * 2),
        "Version released after updates_exp should not be covered"
    );
}

#[test]
fn test_covers_version_perpetual_updates() {
    let now = chrono::Utc::now().timestamp();
    let claims = LicenseClaims {
        license_exp: None,
        updates_exp: None, // Perpetual updates
        tier: "pro".to_string(),
        features: vec![],
        device_id: "".to_string(),
        device_type: "uuid".to_string(),
        product_id: "".to_string(),
    };

    // Should cover any version, even 10 years in the future
    assert!(
        claims.covers_version(now + SECONDS_PER_DAY * ONE_YEAR * 10),
        "Perpetual updates (None) should cover versions released at any time"
    );
}

#[test]
fn test_has_feature_returns_true_for_existing_feature() {
    let claims = LicenseClaims {
        license_exp: None,
        updates_exp: None,
        tier: "pro".to_string(),
        features: vec![
            "export".to_string(),
            "api".to_string(),
            "analytics".to_string(),
        ],
        device_id: "".to_string(),
        device_type: "uuid".to_string(),
        product_id: "".to_string(),
    };

    assert!(claims.has_feature("export"), "Should have export feature");
    assert!(claims.has_feature("api"), "Should have api feature");
    assert!(
        !claims.has_feature("admin"),
        "Should not have admin feature"
    );
}

#[test]
fn test_has_feature_returns_false_for_empty_features() {
    let claims = LicenseClaims {
        license_exp: None,
        updates_exp: None,
        tier: "free".to_string(),
        features: vec![],
        device_id: "".to_string(),
        device_type: "uuid".to_string(),
        product_id: "".to_string(),
    };

    assert!(
        !claims.has_feature("anything"),
        "Empty features should not have any feature"
    );
}

// ============ Edge Cases ============

#[test]
fn test_sign_with_unicode_claims() {
    let (private_key, public_key) = jwt::generate_keypair();
    let claims = LicenseClaims {
        license_exp: None,
        updates_exp: None,
        tier: "プロ".to_string(), // Japanese
        features: vec!["日本語".to_string(), "한국어".to_string()], // Japanese and Korean
        device_id: "デバイス".to_string(),
        device_type: "uuid".to_string(),
        product_id: "商品".to_string(),
    };

    let token = jwt::sign_claims(&claims, &private_key, "ライセンス", "アプリ.com", "JTI")
        .expect("Signing with unicode should succeed");

    let verified = jwt::verify_token(&token, &public_key).expect("Verification should succeed");

    assert_eq!(
        verified.custom.tier, "プロ",
        "Unicode tier should be preserved in token"
    );
    assert!(
        verified.custom.features.contains(&"日本語".to_string()),
        "Unicode features should be preserved in token"
    );
}

#[test]
fn test_sign_with_special_characters() {
    let (private_key, public_key) = jwt::generate_keypair();
    let claims = LicenseClaims {
        license_exp: None,
        updates_exp: None,
        tier: "tier-with\"quotes'and\\slashes".to_string(),
        features: vec![
            "feat:with:colons".to_string(),
            "feat/with/slashes".to_string(),
        ],
        device_id: "device<>&id".to_string(),
        device_type: "uuid".to_string(),
        product_id: "product@#$%".to_string(),
    };

    let token = jwt::sign_claims(&claims, &private_key, "sub", "aud", "jti")
        .expect("Signing with special chars should succeed");

    let verified = jwt::verify_token(&token, &public_key).expect("Verification should succeed");

    assert_eq!(
        verified.custom.tier, claims.tier,
        "Special characters in tier should be preserved"
    );
    assert_eq!(
        verified.custom.device_id, claims.device_id,
        "Special characters in device_id should be preserved"
    );
}

#[test]
fn test_sign_with_empty_features() {
    let (private_key, public_key) = jwt::generate_keypair();
    let claims = LicenseClaims {
        license_exp: None,
        updates_exp: None,
        tier: "free".to_string(),
        features: vec![],
        device_id: "device".to_string(),
        device_type: "uuid".to_string(),
        product_id: "product".to_string(),
    };

    let token = jwt::sign_claims(&claims, &private_key, "sub", "aud", "jti")
        .expect("Signing with empty features should succeed");

    let verified = jwt::verify_token(&token, &public_key).expect("Verification should succeed");

    assert!(
        verified.custom.features.is_empty(),
        "Empty features array should remain empty after roundtrip"
    );
}

#[test]
fn test_sign_with_many_features() {
    let (private_key, public_key) = jwt::generate_keypair();
    let features: Vec<String> = (0..100).map(|i| format!("feature_{}", i)).collect();

    let claims = LicenseClaims {
        license_exp: None,
        updates_exp: None,
        tier: "enterprise".to_string(),
        features: features.clone(),
        device_id: "device".to_string(),
        device_type: "uuid".to_string(),
        product_id: "product".to_string(),
    };

    let token = jwt::sign_claims(&claims, &private_key, "sub", "aud", "jti")
        .expect("Signing with many features should succeed");

    let verified = jwt::verify_token(&token, &public_key).expect("Verification should succeed");

    assert_eq!(
        verified.custom.features.len(),
        100,
        "All 100 features should be preserved in token"
    );
}

// NOTE: Audience verification was removed - signature verification with the
// project's public key is sufficient to prove the token was issued for that project.
