//! First-party JWT token validation.
//!
//! Validates JWTs from trusted first-party apps (Console, mobile, etc.)
//! using JWKS from configured issuers.

use std::collections::HashSet;

use jwt_simple::algorithms::RSAPublicKeyLike;
use jwt_simple::prelude::{Token, VerificationOptions};
use serde::{Deserialize, Serialize};

use crate::config::TrustedIssuer;
use crate::error::{AppError, Result};

use super::jwks::JwksCache;

/// Claims from a first-party app JWT (Console, mobile, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirstPartyTokenClaims {
    /// Subject - the user ID from the issuing app
    pub sub: String,
    /// User email
    pub email: String,
}

/// Result of validating a first-party token
#[derive(Debug, Clone)]
pub struct ValidatedFirstPartyToken {
    /// The validated claims
    pub claims: FirstPartyTokenClaims,
    /// The issuer URL that was validated against
    pub issuer: String,
}

/// Validate a first-party JWT token against configured trusted issuers.
///
/// This function:
/// 1. Decodes the token header to get the key ID (kid)
/// 2. Decodes claims (unverified) to get the issuer (iss)
/// 3. Finds a matching trusted issuer configuration
/// 4. Fetches the public key from the issuer's JWKS
/// 5. Verifies the token signature and claims
pub async fn validate_first_party_token(
    token: &str,
    trusted_issuers: &[TrustedIssuer],
    jwks_cache: &JwksCache,
) -> Result<ValidatedFirstPartyToken> {
    // 1. Decode token metadata to get key ID
    let metadata = Token::decode_metadata(token)
        .map_err(|e| AppError::JwtValidationFailed(format!("Invalid token format: {}", e)))?;

    let kid = metadata.key_id().ok_or(AppError::MissingKeyId)?;

    // 2. Decode claims (unverified) to get issuer
    #[derive(Deserialize)]
    struct UnverifiedClaims {
        iss: Option<String>,
    }

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::JwtValidationFailed(
            "Invalid token format".to_string(),
        ));
    }

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::JwtValidationFailed("Invalid token encoding".to_string()))?;

    let unverified: UnverifiedClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AppError::JwtValidationFailed(format!("Invalid token payload: {}", e)))?;

    let issuer = unverified
        .iss
        .ok_or_else(|| AppError::JwtValidationFailed("Missing 'iss' claim".to_string()))?;

    // 3. Find matching trusted issuer
    let trusted = trusted_issuers
        .iter()
        .find(|i| i.issuer == issuer)
        .ok_or(AppError::UntrustedIssuer)?;

    // 4. Get public key from JWKS cache
    let public_key = jwks_cache.get_key(&trusted.jwks_url, kid).await?;

    // 5. Verify token signature and claims
    let mut allowed_issuers = HashSet::new();
    allowed_issuers.insert(trusted.issuer.clone());

    let mut allowed_audiences = HashSet::new();
    allowed_audiences.insert(trusted.audience.clone());

    let options = VerificationOptions {
        allowed_issuers: Some(allowed_issuers),
        allowed_audiences: Some(allowed_audiences),
        ..Default::default()
    };

    let verified_claims = public_key
        .verify_token::<FirstPartyTokenClaims>(token, Some(options))
        .map_err(|e| AppError::JwtValidationFailed(format!("Token verification failed: {}", e)))?;

    Ok(ValidatedFirstPartyToken {
        claims: verified_claims.custom,
        issuer: trusted.issuer.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_party_claims_deserialize() {
        let json = r#"{"sub": "user123", "email": "test@example.com"}"#;
        let claims: FirstPartyTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.email, "test@example.com");
    }
}
