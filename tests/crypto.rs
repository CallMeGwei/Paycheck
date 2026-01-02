//! Crypto module tests (envelope encryption, secret hashing)

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use paycheck::crypto::{MasterKey, hash_secret};

#[test]
fn test_generate_master_key() {
    let key = MasterKey::generate();
    assert!(!key.is_empty());

    // Should be valid base64 that decodes to 32 bytes
    let decoded = BASE64.decode(&key).unwrap();
    assert_eq!(decoded.len(), 32);
}

#[test]
fn test_from_base64_valid() {
    let key_b64 = MasterKey::generate();
    let result = MasterKey::from_base64(&key_b64);
    assert!(result.is_ok());
}

#[test]
fn test_from_base64_invalid_length() {
    let short_key = BASE64.encode([0u8; 16]); // Only 16 bytes
    let result = MasterKey::from_base64(&short_key);
    assert!(result.is_err());
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let project_id = "project-123";
    let private_key = [42u8; 32]; // Simulated Ed25519 private key

    let encrypted = master_key
        .encrypt_private_key(project_id, &private_key)
        .unwrap();

    let decrypted = master_key
        .decrypt_private_key(project_id, &encrypted)
        .unwrap();

    assert_eq!(decrypted, private_key);
}

#[test]
fn test_different_projects_different_ciphertext() {
    let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let private_key = [42u8; 32];

    let encrypted1 = master_key
        .encrypt_private_key("project-1", &private_key)
        .unwrap();
    let encrypted2 = master_key
        .encrypt_private_key("project-2", &private_key)
        .unwrap();

    // Same plaintext, different project IDs → different ciphertext
    // (Also different due to random nonce, but DEK derivation also differs)
    assert_ne!(encrypted1, encrypted2);
}

#[test]
fn test_wrong_project_id_fails() {
    let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let private_key = [42u8; 32];

    let encrypted = master_key
        .encrypt_private_key("project-1", &private_key)
        .unwrap();

    // Try to decrypt with wrong project ID
    let result = master_key.decrypt_private_key("project-2", &encrypted);
    assert!(result.is_err());
}

#[test]
fn test_hash_secret() {
    let key = "PC-ABCD-1234-WXYZ-5678";
    let hash = hash_secret(key);

    // Should be 64 hex chars (256 bits)
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

    // Same input should produce same hash
    assert_eq!(hash, hash_secret(key));

    // Different input should produce different hash
    assert_ne!(hash, hash_secret("PC-DIFFERENT-KEY"));
}
