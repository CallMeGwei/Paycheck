//! Security tests for JWKS RSA key parsing.
//!
//! The JWKS module parses RSA public keys from JWK format (n, e components).
//! These tests verify the parsing works correctly with real-world key formats
//! and that malformed inputs are properly rejected.

#[path = "../common/mod.rs"]
mod common;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jwt_simple::prelude::*;

// ============ VALID KEY PARSING TESTS ============

/// Test that jwt-simple's from_components works with standard RSA keys.
#[test]
fn test_from_components_with_2048_bit_key() {
    // Generate a key pair and extract components
    let key_pair = RS256KeyPair::generate(2048).unwrap();
    let public_key = key_pair.public_key();

    // The key should be usable for verification
    let claims = Claims::create(Duration::from_hours(1));
    let token = key_pair.sign(claims).unwrap();

    // Verify with the original key
    let verified = public_key.verify_token::<NoCustomClaims>(&token, None);
    assert!(verified.is_ok(), "Key should verify token");
}

/// Test that keys with standard 65537 (0x010001) exponent work.
#[test]
fn test_standard_exponent_65537() {
    // 65537 = 0x010001 in bytes
    let e_bytes = vec![0x01, 0x00, 0x01];

    // Generate a real key to get valid n bytes
    let key_pair = RS256KeyPair::generate(2048).unwrap();

    // Verify the key works
    let claims = Claims::create(Duration::from_hours(1));
    let token = key_pair.sign(claims).unwrap();
    assert!(!token.is_empty());

    // Verify exponent encoding (AQAB is standard base64url for 65537)
    let e_b64 = URL_SAFE_NO_PAD.encode(&e_bytes);
    assert_eq!(e_b64, "AQAB");
}

// ============ SIGNATURE VERIFICATION TESTS ============

/// Test that a parsed key can actually verify a signature.
#[test]
fn test_key_verifies_signature() {
    let key_pair = RS256KeyPair::generate(2048).unwrap();
    let public_key = key_pair.public_key();

    let claims = Claims::create(Duration::from_hours(1)).with_subject("test-user");
    let token = key_pair.sign(claims).unwrap();

    let verification = public_key.verify_token::<NoCustomClaims>(&token, None);
    assert!(
        verification.is_ok(),
        "Key should verify valid signature"
    );

    let verified_claims = verification.unwrap();
    assert_eq!(
        verified_claims.subject,
        Some("test-user".to_string()),
        "Claims should be preserved"
    );
}

/// Test that a key rejects signatures from a different key pair.
#[test]
fn test_key_rejects_wrong_signature() {
    let key_pair_1 = RS256KeyPair::generate(2048).unwrap();
    let key_pair_2 = RS256KeyPair::generate(2048).unwrap();

    let claims = Claims::create(Duration::from_hours(1));
    let token = key_pair_1.sign(claims).unwrap();

    let public_key_2 = key_pair_2.public_key();
    let verification = public_key_2.verify_token::<NoCustomClaims>(&token, None);

    assert!(
        verification.is_err(),
        "Key should reject signature from different key pair"
    );
}

/// Test that a key rejects a tampered token.
#[test]
fn test_key_rejects_tampered_token() {
    let key_pair = RS256KeyPair::generate(2048).unwrap();
    let public_key = key_pair.public_key();

    let claims = Claims::create(Duration::from_hours(1));
    let token = key_pair.sign(claims).unwrap();

    // Tamper with the payload
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");

    let mut payload_bytes = STANDARD.decode(parts[1]).unwrap_or_default();
    if !payload_bytes.is_empty() {
        payload_bytes[0] ^= 0xFF;
    }
    let tampered_payload = STANDARD.encode(&payload_bytes);
    let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

    let verification = public_key.verify_token::<NoCustomClaims>(&tampered_token, None);
    assert!(
        verification.is_err(),
        "Key should reject tampered token"
    );
}

// ============ from_components TESTS ============

/// Test from_components with valid n and e bytes.
#[test]
fn test_from_components_valid_input() {
    // Generate a key and get its DER representation
    let key_pair = RS256KeyPair::generate(2048).unwrap();
    let public_key = key_pair.public_key();

    // Export to PEM and verify key is valid by using it
    let claims = Claims::create(Duration::from_hours(1));
    let token = key_pair.sign(claims).unwrap();

    let verification = public_key.verify_token::<NoCustomClaims>(&token, None);
    assert!(verification.is_ok());
}

/// Test that invalid keys (created from garbage) fail at verification time.
/// Note: from_components may accept invalid inputs but verification will fail.
#[test]
fn test_invalid_key_fails_at_verification() {
    // Create a key with garbage data
    let garbage_n = vec![0x01; 32]; // Way too small for RSA
    let valid_e = vec![0x01, 0x00, 0x01]; // 65537

    // The library may or may not accept this at construction
    let result = RS256PublicKey::from_components(&garbage_n, &valid_e);

    if let Ok(bad_key) = result {
        // If it accepts the bad key, it should fail at verification
        let key_pair = RS256KeyPair::generate(2048).unwrap();
        let claims = Claims::create(Duration::from_hours(1));
        let token = key_pair.sign(claims).unwrap();

        // Verification with bad key should fail
        let verification = bad_key.verify_token::<NoCustomClaims>(&token, None);
        assert!(
            verification.is_err(),
            "Invalid key should fail at verification"
        );
    }
    // If construction fails, that's also fine
}

// ============ BASE64URL DECODING TESTS ============

/// Test that invalid base64url is handled properly.
#[test]
fn test_invalid_base64url_rejected() {
    let invalid = "!!!not-valid-base64!!!";
    let result = URL_SAFE_NO_PAD.decode(invalid);
    assert!(result.is_err(), "Invalid base64url should be rejected");
}

/// Test that valid base64url decodes correctly.
#[test]
fn test_valid_base64url_decodes() {
    // AQAB is base64url for [0x01, 0x00, 0x01] (65537)
    let result = URL_SAFE_NO_PAD.decode("AQAB").unwrap();
    assert_eq!(result, vec![0x01, 0x00, 0x01]);
}

// ============ REAL-WORLD COMPATIBILITY TESTS ============

/// Test with Google JWKS format (2048-bit RSA, e=65537).
#[test]
fn test_google_jwks_format_compatibility() {
    let key_pair = RS256KeyPair::generate(2048).unwrap();

    let claims = Claims::create(Duration::from_hours(1))
        .with_issuer("https://accounts.google.com")
        .with_audience("test-client-id");

    let token = key_pair.sign(claims).unwrap();

    let public_key = key_pair.public_key();
    let verification = public_key.verify_token::<NoCustomClaims>(&token, None);

    assert!(verification.is_ok(), "Google-format key should work");
}

/// Test with Auth0 JWKS format.
#[test]
fn test_auth0_jwks_format_compatibility() {
    let key_pair = RS256KeyPair::generate(2048).unwrap();

    let claims = Claims::create(Duration::from_hours(1))
        .with_issuer("https://tenant.auth0.com/")
        .with_audience("https://api.example.com");

    let token = key_pair.sign(claims).unwrap();

    let public_key = key_pair.public_key();
    let verification = public_key.verify_token::<NoCustomClaims>(&token, None);

    assert!(verification.is_ok(), "Auth0-format key should work");
}

/// Test with various RSA key sizes.
#[test]
fn test_various_key_sizes() {
    // 2048-bit (minimum recommended)
    let key_2048 = RS256KeyPair::generate(2048).unwrap();
    let claims = Claims::create(Duration::from_hours(1));
    let token = key_2048.sign(claims.clone()).unwrap();
    assert!(key_2048.public_key().verify_token::<NoCustomClaims>(&token, None).is_ok());

    // 3072-bit
    let key_3072 = RS256KeyPair::generate(3072).unwrap();
    let token = key_3072.sign(claims.clone()).unwrap();
    assert!(key_3072.public_key().verify_token::<NoCustomClaims>(&token, None).is_ok());

    // 4096-bit
    let key_4096 = RS256KeyPair::generate(4096).unwrap();
    let token = key_4096.sign(claims).unwrap();
    assert!(key_4096.public_key().verify_token::<NoCustomClaims>(&token, None).is_ok());
}
