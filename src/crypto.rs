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
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::error::{AppError, Result};

/// Nonce size for AES-GCM (96 bits)
const NONCE_SIZE: usize = 12;

/// Master key size (256 bits for AES-256)
const MASTER_KEY_SIZE: usize = 32;

/// Magic bytes to identify encrypted data
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
        use rand::rngs::OsRng;
        let mut key = [0u8; MASTER_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
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

}

/// Email hasher with a stable HMAC key.
///
/// The HMAC key is stored encrypted in the database and survives master key rotation.
/// This ensures email hashes remain valid after rotation (unlike deriving from master key).
///
/// Thread-safe and cheaply cloneable.
#[derive(Clone)]
pub struct EmailHasher {
    hmac_key: [u8; 32],
}

impl EmailHasher {
    /// Key name in system_config table
    pub const CONFIG_KEY: &'static str = "email_hmac_key";

    /// Create an EmailHasher from a raw 32-byte HMAC key.
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { hmac_key: key }
    }

    /// Generate a new random HMAC key.
    pub fn generate_key() -> [u8; 32] {
        use rand::RngCore;
        use rand::rngs::OsRng;
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Hash an email address for storage/lookup using HMAC-SHA256.
    ///
    /// This is secure against rainbow table attacks because the HMAC key is
    /// a secret stored encrypted in the database. An attacker with only
    /// database access cannot precompute hashes without the master key to
    /// decrypt the HMAC key.
    ///
    /// The email is normalized (NFC Unicode, lowercase, trimmed) before hashing
    /// to ensure consistent lookups regardless of input encoding.
    pub fn hash(&self, email: &str) -> String {
        use hmac::{Hmac, Mac};
        use unicode_normalization::UnicodeNormalization;

        // Normalize email: NFC Unicode form, lowercase, trimmed
        let normalized: String = email.nfc().collect();
        let normalized = normalized.to_lowercase();
        let normalized = normalized.trim();

        // Compute HMAC-SHA256
        let mut mac: Hmac<Sha256> = Mac::new_from_slice(&self.hmac_key)
            .expect("HMAC can take key of any size");
        mac.update(normalized.as_bytes());

        hex::encode(mac.finalize().into_bytes())
    }

    /// Get the raw HMAC key bytes (for encryption/storage).
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.hmac_key
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
