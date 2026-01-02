//! Envelope encryption for sensitive data (private keys, license keys, etc).
//!
//! Uses HKDF to derive per-entity data encryption keys (DEKs) from a master key,
//! then encrypts data with AES-256-GCM.
//!
//! Format of encrypted data: MAGIC (4 bytes) || nonce (12 bytes) || ciphertext
//!
//! Used for:
//! - Project Ed25519 private keys (DEK derived from project_id)
//! - Organization payment configs (DEK derived from org_id)
//! - License keys (DEK derived from project_id)

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::error::{AppError, Result};

/// Nonce size for AES-GCM (96 bits)
const NONCE_SIZE: usize = 12;

/// Master key size (256 bits for AES-256)
const MASTER_KEY_SIZE: usize = 32;

/// Magic bytes to identify encrypted keys (helps detect unencrypted legacy keys)
const ENCRYPTED_MAGIC: &[u8] = b"ENC1";

/// Holds the master encryption key for envelope encryption.
/// The master key is used to derive per-project DEKs via HKDF.
#[derive(Clone)]
pub struct MasterKey {
    key: [u8; MASTER_KEY_SIZE],
}

impl MasterKey {
    /// Create a MasterKey from a base64-encoded string.
    /// The decoded key must be exactly 32 bytes.
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let decoded = BASE64
            .decode(encoded.trim())
            .map_err(|e| AppError::Internal(format!("Invalid master key encoding: {}", e)))?;

        if decoded.len() != MASTER_KEY_SIZE {
            return Err(AppError::Internal(format!(
                "Master key must be {} bytes, got {}",
                MASTER_KEY_SIZE,
                decoded.len()
            )));
        }

        let mut key = [0u8; MASTER_KEY_SIZE];
        key.copy_from_slice(&decoded);
        Ok(Self { key })
    }

    /// Generate a new random master key (for initial setup).
    /// Returns the key as a base64-encoded string.
    pub fn generate() -> String {
        use rand::RngCore;
        let mut key = [0u8; MASTER_KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        BASE64.encode(key)
    }

    /// Create a MasterKey from raw bytes.
    /// Note: For production, prefer `from_base64` with a securely stored key.
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Derive a per-project data encryption key using HKDF.
    fn derive_dek(&self, project_id: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"paycheck-v1"), &self.key);
        let mut dek = [0u8; 32];
        // Using project_id as the info parameter ensures each project gets a unique DEK
        hk.expand(project_id.as_bytes(), &mut dek)
            .expect("HKDF expand should not fail with valid length");
        dek
    }

    /// Encrypt a private key for storage.
    /// Returns: MAGIC (4 bytes) || nonce (12 bytes) || ciphertext
    pub fn encrypt_private_key(&self, project_id: &str, private_key: &[u8]) -> Result<Vec<u8>> {
        use rand::RngCore;

        let dek = self.derive_dek(project_id);
        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|e| AppError::Internal(format!("Failed to create cipher: {}", e)))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, private_key)
            .map_err(|e| AppError::Internal(format!("Encryption failed: {}", e)))?;

        // Combine: magic || nonce || ciphertext
        let mut result = Vec::with_capacity(ENCRYPTED_MAGIC.len() + NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(ENCRYPTED_MAGIC);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt a private key from storage.
    /// Accepts: MAGIC (4 bytes) || nonce (12 bytes) || ciphertext
    pub fn decrypt_private_key(&self, project_id: &str, encrypted: &[u8]) -> Result<Vec<u8>> {
        // Check magic bytes
        if encrypted.len() < ENCRYPTED_MAGIC.len() + NONCE_SIZE + 1 {
            return Err(AppError::Internal("Encrypted data too short".into()));
        }

        if &encrypted[..ENCRYPTED_MAGIC.len()] != ENCRYPTED_MAGIC {
            return Err(AppError::Internal(
                "Invalid encrypted data format (missing magic bytes)".into(),
            ));
        }

        let dek = self.derive_dek(project_id);
        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|e| AppError::Internal(format!("Failed to create cipher: {}", e)))?;

        // Extract nonce and ciphertext
        let nonce_start = ENCRYPTED_MAGIC.len();
        let nonce_end = nonce_start + NONCE_SIZE;
        let nonce = Nonce::from_slice(&encrypted[nonce_start..nonce_end]);
        let ciphertext = &encrypted[nonce_end..];

        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| AppError::Internal(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }

    /// Check if data appears to be encrypted (has magic bytes).
    pub fn is_encrypted(data: &[u8]) -> bool {
        data.len() >= ENCRYPTED_MAGIC.len() && &data[..ENCRYPTED_MAGIC.len()] == ENCRYPTED_MAGIC
    }
}

/// Hash a secret for database lookups (license keys, API keys, redemption codes).
/// Uses SHA-256 with application salt, returns lowercase hex string.
pub fn hash_secret(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"paycheck-v1:");
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let master_key = MasterKey::from_base64(&key_b64).unwrap();
        assert_eq!(master_key.key.len(), 32);
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

        // Verify it's marked as encrypted
        assert!(MasterKey::is_encrypted(&encrypted));

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
    fn test_is_encrypted_detection() {
        // Unencrypted 32-byte key (raw Ed25519)
        let raw_key = [0u8; 32];
        assert!(!MasterKey::is_encrypted(&raw_key));

        // Encrypted key has magic bytes
        let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
        let encrypted = master_key
            .encrypt_private_key("project-1", &raw_key)
            .unwrap();
        assert!(MasterKey::is_encrypted(&encrypted));
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
}
