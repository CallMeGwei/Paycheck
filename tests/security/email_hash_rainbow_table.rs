//! Email hash security tests.
//!
//! These tests verify that the HMAC-based email hashing is secure against
//! rainbow table attacks while maintaining required functional properties.

#[path = "../common/mod.rs"]
mod common;
use common::*;

use paycheck::crypto::EmailHasher;
use paycheck::db::queries;

// ============================================================================
// Security Tests - HMAC prevents rainbow table attacks
// ============================================================================

/// The hash uses HMAC which requires the secret key.
/// An attacker cannot reproduce it from source code alone.
#[test]
fn test_email_hash_requires_secret_key() {
    use sha2::{Digest, Sha256};
    use unicode_normalization::UnicodeNormalization;

    let email_hasher = test_email_hasher();
    let email = "target@example.com";

    // Attacker tries to reproduce using a naive SHA256 approach
    let normalized: String = email.nfc().collect();
    let normalized = normalized.to_lowercase();
    let normalized = normalized.trim();

    let mut hasher = Sha256::new();
    hasher.update(b"paycheck-email-v1:");
    hasher.update(normalized.as_bytes());
    let attacker_guess = hex::encode(hasher.finalize());

    // Server's actual hash using HMAC
    let actual_secure_hash = email_hasher.hash(email);

    // Attacker's guess does NOT match
    assert_ne!(
        attacker_guess, actual_secure_hash,
        "Attacker cannot reproduce HMAC hash without the secret key"
    );
}

/// Different HMAC keys produce different hashes for the same email.
/// This proves the hash depends on the secret key.
#[test]
fn test_different_keys_produce_different_hashes() {
    let hasher1 = EmailHasher::from_bytes([1u8; 32]);
    let hasher2 = EmailHasher::from_bytes([2u8; 32]);

    let email = "test@example.com";

    let hash1 = hasher1.hash(email);
    let hash2 = hasher2.hash(email);

    assert_ne!(
        hash1, hash2,
        "Different HMAC keys must produce different hashes"
    );
}

/// Without the HMAC key, an attacker cannot precompute valid hashes.
#[test]
fn test_rainbow_table_attack_fails() {
    use sha2::{Digest, Sha256};
    use unicode_normalization::UnicodeNormalization;

    let email_hasher = test_email_hasher();

    let common_emails = vec![
        "john@gmail.com",
        "jane@gmail.com",
        "admin@company.com",
        "test@example.com",
    ];

    // Attacker tries to build a rainbow table using naive SHA256
    let attacker_rainbow_table: std::collections::HashMap<String, &str> = common_emails
        .iter()
        .map(|email| {
            let normalized: String = email.nfc().collect();
            let normalized = normalized.to_lowercase();
            let mut hasher = Sha256::new();
            hasher.update(b"paycheck-email-v1:");
            hasher.update(normalized.as_bytes());
            (hex::encode(hasher.finalize()), *email)
        })
        .collect();

    // Server computes hash using the secure HMAC-based function
    let victim_email = "john@gmail.com";
    let secure_hash = email_hasher.hash(victim_email);

    // Attacker's rainbow table CANNOT reverse the secure hash
    let recovered = attacker_rainbow_table.get(&secure_hash);
    assert!(
        recovered.is_none(),
        "Rainbow table attack must fail - attacker cannot reverse HMAC-based hashes"
    );
}

// ============================================================================
// Functional Property Tests - hash still works correctly
// ============================================================================

/// The hash function is deterministic (same input = same output).
/// This is required for database lookups to work.
#[test]
fn test_hash_is_deterministic() {
    let email_hasher = test_email_hasher();
    let email = "test@example.com";

    let hash1 = email_hasher.hash(email);
    let hash2 = email_hasher.hash(email);
    let hash3 = email_hasher.hash(email);

    assert_eq!(hash1, hash2, "Hash must be deterministic");
    assert_eq!(hash2, hash3, "Hash must be deterministic");
}

/// The hash function is case-insensitive.
#[test]
fn test_hash_case_insensitive() {
    let email_hasher = test_email_hasher();

    let hash1 = email_hasher.hash("Test@Example.COM");
    let hash2 = email_hasher.hash("test@example.com");

    assert_eq!(hash1, hash2, "Hash should be case-insensitive");
}

/// The hash function handles unicode normalization.
#[test]
fn test_hash_unicode_normalized() {
    let email_hasher = test_email_hasher();

    // NFC form: é as single codepoint (U+00E9)
    let email_nfc = "caf\u{00E9}@example.com";
    // NFD form: e + combining acute accent (U+0065 U+0301)
    let email_nfd = "cafe\u{0301}@example.com";

    let hash_nfc = email_hasher.hash(email_nfc);
    let hash_nfd = email_hasher.hash(email_nfd);

    assert_eq!(
        hash_nfc, hash_nfd,
        "Hash should normalize unicode to NFC form"
    );
}

/// The hash function trims whitespace.
#[test]
fn test_hash_trims_whitespace() {
    let email_hasher = test_email_hasher();

    let hash1 = email_hasher.hash("  test@example.com  ");
    let hash2 = email_hasher.hash("test@example.com");

    assert_eq!(hash1, hash2, "Hash should trim whitespace");
}

// ============================================================================
// Integration test with database
// ============================================================================

/// Test that the secure hash works correctly in a database scenario.
#[test]
fn test_secure_hash_database_lookup() {
    use paycheck::models::CreateLicense;

    let state = create_test_app_state();
    let conn = state.db.get().unwrap();

    // Setup
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    // Create license with secure email hash
    let email = "customer@example.com";
    let secure_hash = state.email_hasher.hash(email);

    let input = CreateLicense {
        email_hash: Some(secure_hash.clone()),
        customer_id: None,
        expires_at: Some(future_timestamp(ONE_YEAR)),
        updates_expires_at: Some(future_timestamp(ONE_YEAR)),
        payment_provider: None,
        payment_provider_customer_id: None,
        payment_provider_subscription_id: None,
        payment_provider_order_id: Some("order-123".to_string()),
    };
    let license = queries::create_license(&conn, &project.id, &product.id, &input).unwrap();

    // Verify we can look it up using the same email
    let lookup_hash = state.email_hasher.hash(email);
    let found = queries::get_licenses_by_email_hash(&conn, &project.id, &lookup_hash).unwrap();

    assert_eq!(found.len(), 1, "Should find the license by email hash");
    assert_eq!(found[0].id, license.id);

    // Different email should not find it
    let wrong_hash = state.email_hasher.hash("other@example.com");
    let not_found = queries::get_licenses_by_email_hash(&conn, &project.id, &wrong_hash).unwrap();

    assert!(not_found.is_empty(), "Wrong email should not find the license");
}
