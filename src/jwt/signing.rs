use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL, Engine};
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{SigningKey, VerifyingKey};
use jwt_simple::prelude::*;
use rand::rngs::OsRng;
use serde::Deserialize;

use crate::error::{AppError, Result};
use super::LicenseClaims;

/// Generate a new Ed25519 key pair
/// Returns (private_key_bytes, public_key_base64)
pub fn generate_keypair() -> (Vec<u8>, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_bytes = signing_key.to_bytes().to_vec();
    let public_b64 = BASE64.encode(verifying_key.to_bytes());

    (private_bytes, public_b64)
}

/// Sign claims with an Ed25519 private key
pub fn sign_claims(
    claims: &LicenseClaims,
    private_key: &[u8],
    subject: &str,
    audience: &str,
    jti: &str,
) -> Result<String> {
    if private_key.len() != 32 {
        return Err(AppError::Internal("Invalid private key length".into()));
    }

    let key_bytes: [u8; 32] = private_key
        .try_into()
        .map_err(|_| AppError::Internal("Failed to convert key bytes".into()))?;

    let signing_key = SigningKey::from_bytes(&key_bytes);
    let key_pair = Ed25519KeyPair::from_bytes(&signing_key.to_keypair_bytes())
        .map_err(|e| AppError::Internal(format!("Failed to create key pair: {}", e)))?;

    // Create claims with standard fields handled by jwt-simple
    let jwt_claims = Claims::with_custom_claims(claims.clone(), Duration::from_secs(3600))
        .with_issuer("paycheck")
        .with_subject(subject)
        .with_audience(audience)
        .with_jwt_id(jti);

    let token = key_pair
        .sign(jwt_claims)
        .map_err(|e| AppError::Internal(format!("Failed to sign token: {}", e)))?;

    Ok(token)
}

/// Decode a JWT without verification to extract claims
/// Used to get product_id to look up the signing key
/// MUST be followed by verify_token() before trusting any claims
pub fn decode_unverified(token: &str) -> Result<LicenseClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::BadRequest("Invalid token format".into()));
    }

    let payload = BASE64_URL
        .decode(parts[1])
        .map_err(|_| AppError::BadRequest("Invalid token encoding".into()))?;

    #[derive(Deserialize)]
    struct TokenPayload {
        #[serde(flatten)]
        claims: LicenseClaims,
    }

    let payload: TokenPayload = serde_json::from_slice(&payload)
        .map_err(|_| AppError::BadRequest("Invalid token payload".into()))?;

    Ok(payload.claims)
}

/// Verify a JWT and extract claims
/// Validates signature, expiration, issuer ("paycheck"), and audience (expected_audience)
pub fn verify_token(
    token: &str,
    public_key_b64: &str,
    expected_audience: &str,
) -> Result<JWTClaims<LicenseClaims>> {
    verify_token_internal(token, public_key_b64, expected_audience, false)
}

/// Verify a JWT signature but allow expired tokens (for refresh flow)
/// Validates signature, issuer ("paycheck"), and audience - but NOT expiration
pub fn verify_token_allow_expired(
    token: &str,
    public_key_b64: &str,
    expected_audience: &str,
) -> Result<JWTClaims<LicenseClaims>> {
    verify_token_internal(token, public_key_b64, expected_audience, true)
}

fn verify_token_internal(
    token: &str,
    public_key_b64: &str,
    expected_audience: &str,
    allow_expired: bool,
) -> Result<JWTClaims<LicenseClaims>> {
    let public_bytes = BASE64
        .decode(public_key_b64)
        .map_err(|e| AppError::Internal(format!("Invalid public key encoding: {}", e)))?;

    if public_bytes.len() != 32 {
        return Err(AppError::Internal("Invalid public key length".into()));
    }

    let key_bytes: [u8; 32] = public_bytes
        .try_into()
        .map_err(|_| AppError::Internal("Failed to convert key bytes".into()))?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| AppError::Internal(format!("Invalid public key: {}", e)))?;

    let public_key = Ed25519PublicKey::from_bytes(&verifying_key.to_bytes())
        .map_err(|e| AppError::Internal(format!("Failed to create public key: {}", e)))?;

    let mut options = VerificationOptions::default();
    options.allowed_issuers = Some(std::collections::HashSet::from(["paycheck".to_string()]));
    options.allowed_audiences = Some(std::collections::HashSet::from([expected_audience.to_string()]));

    if allow_expired {
        // Set a large time tolerance to effectively ignore expiration
        // 10 years in seconds - allows tokens expired up to 10 years ago
        options.time_tolerance = Some(Duration::from_secs(10 * 365 * 24 * 60 * 60));
    }

    let claims = public_key
        .verify_token::<LicenseClaims>(token, Some(options))
        .map_err(|e| AppError::BadRequest(format!("Invalid token: {}", e)))?;

    Ok(claims)
}
