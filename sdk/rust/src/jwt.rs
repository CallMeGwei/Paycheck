//! JWT decoding and verification utilities

use crate::error::{PaycheckError, PaycheckErrorCode, Result};
use crate::types::LicenseClaims;
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::time::{SystemTime, UNIX_EPOCH};

/// Decode a JWT and return the claims.
///
/// Does NOT verify the signature - use `verify_token` for that.
pub fn decode_token(token: &str) -> Result<LicenseClaims> {
    let parts: Vec<&str> = token.split('.').collect();

    if parts.len() != 3 {
        return Err(PaycheckError::new(
            PaycheckErrorCode::ValidationError,
            "Invalid JWT format",
        ));
    }

    let payload = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| {
        PaycheckError::new(PaycheckErrorCode::ValidationError, "Failed to decode JWT payload")
    })?;

    let claims: LicenseClaims = serde_json::from_slice(&payload).map_err(|_| {
        PaycheckError::new(PaycheckErrorCode::ValidationError, "Failed to parse JWT claims")
    })?;

    Ok(claims)
}

/// Verify a JWT signature using Ed25519.
///
/// # Arguments
/// * `token` - The JWT token to verify
/// * `public_key` - Base64-encoded Ed25519 public key (32 bytes)
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
pub fn verify_token(token: &str, public_key: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    // Decode public key from base64
    let public_key_bytes = match STANDARD.decode(public_key) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Convert to VerifyingKey
    let verifying_key: VerifyingKey = match public_key_bytes.try_into() {
        Ok(bytes) => match VerifyingKey::from_bytes(&bytes) {
            Ok(key) => key,
            Err(_) => return false,
        },
        Err(_) => return false,
    };

    // Decode signature from base64url
    let signature_bytes = match URL_SAFE_NO_PAD.decode(parts[2]) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // The message is "header.payload"
    let message = format!("{}.{}", parts[0], parts[1]);

    // Verify
    verifying_key.verify(message.as_bytes(), &signature).is_ok()
}

/// Verify a JWT and return the claims if valid.
///
/// # Arguments
/// * `token` - The JWT token to verify
/// * `public_key` - Base64-encoded Ed25519 public key
///
/// # Returns
/// The decoded claims if signature is valid, error otherwise.
pub fn verify_and_decode_token(token: &str, public_key: &str) -> Result<LicenseClaims> {
    if !verify_token(token, public_key) {
        return Err(PaycheckError::new(
            PaycheckErrorCode::ValidationError,
            "Invalid JWT signature",
        ));
    }

    decode_token(token)
}

/// Get the current Unix timestamp
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Check if the JWT's exp claim has passed.
///
/// This is for transport security, not license validity.
pub fn is_jwt_expired(claims: &LicenseClaims) -> bool {
    claims.exp < now()
}

/// Check if the license has expired (license_exp claim).
///
/// This is the actual license validity check.
pub fn is_license_expired(claims: &LicenseClaims) -> bool {
    match claims.license_exp {
        None => false, // Perpetual license
        Some(exp) => exp < now(),
    }
}

/// Check if the license covers a specific version (by its release timestamp).
pub fn covers_version(claims: &LicenseClaims, version_timestamp: i64) -> bool {
    match claims.updates_exp {
        None => true, // All versions covered
        Some(exp) => version_timestamp <= exp,
    }
}

/// Check if the license has a specific feature.
pub fn has_feature(claims: &LicenseClaims, feature: &str) -> bool {
    claims.features.iter().any(|f| f == feature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_token() {
        // This is a test token with known claims
        // Header: {"alg":"EdDSA","typ":"JWT"}
        // Payload: {"iss":"paycheck","sub":"license-123","aud":"test.com","jti":"jti-123","iat":1704067200,"exp":1704070800,"license_exp":null,"updates_exp":null,"tier":"pro","features":["export"],"device_id":"device-123","device_type":"uuid","product_id":"product-123"}
        let token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwYXljaGVjayIsInN1YiI6ImxpY2Vuc2UtMTIzIiwiYXVkIjoidGVzdC5jb20iLCJqdGkiOiJqdGktMTIzIiwiaWF0IjoxNzA0MDY3MjAwLCJleHAiOjE3MDQwNzA4MDAsImxpY2Vuc2VfZXhwIjpudWxsLCJ1cGRhdGVzX2V4cCI6bnVsbCwidGllciI6InBybyIsImZlYXR1cmVzIjpbImV4cG9ydCJdLCJkZXZpY2VfaWQiOiJkZXZpY2UtMTIzIiwiZGV2aWNlX3R5cGUiOiJ1dWlkIiwicHJvZHVjdF9pZCI6InByb2R1Y3QtMTIzIn0.signature";

        let claims = decode_token(token).unwrap();
        assert_eq!(claims.iss, "paycheck");
        assert_eq!(claims.tier, "pro");
        assert!(has_feature(&claims, "export"));
        assert!(!has_feature(&claims, "nonexistent"));
    }
}
