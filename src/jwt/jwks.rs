//! JWKS (JSON Web Key Set) fetching and caching.
//!
//! This module handles fetching and caching public keys from JWKS endpoints
//! for validating JWTs from trusted issuers.
//!
//! Features:
//! - Automatic caching with 1-hour TTL
//! - Retry with exponential backoff on fetch failures
//! - Stale cache fallback when all retries are exhausted

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use jwt_simple::prelude::*;
use serde::Deserialize;

use crate::error::{AppError, Result};

/// Cache duration for JWKS keys (1 hour)
const CACHE_DURATION: Duration = Duration::from_secs(3600);

/// Maximum age for stale cache fallback (24 hours)
/// If cache is older than this, we won't use it even as fallback
const MAX_STALE_DURATION: Duration = Duration::from_secs(86400);

/// Number of retry attempts for JWKS fetch
const FETCH_RETRY_ATTEMPTS: u32 = 3;

/// Base delay for exponential backoff (100ms, 200ms, 400ms)
const FETCH_RETRY_BASE_DELAY_MS: u64 = 100;

/// A cached JWKS with its keys and fetch timestamp
struct CachedJwks {
    /// Map from key ID (kid) to public key
    keys: HashMap<String, RS256PublicKey>,
    /// When the JWKS was fetched
    fetched_at: Instant,
}

impl CachedJwks {
    fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() > CACHE_DURATION
    }

    /// Check if the cache is too old to use even as a fallback
    fn is_expired(&self) -> bool {
        self.fetched_at.elapsed() > MAX_STALE_DURATION
    }
}

/// Cache for JWKS keys from multiple issuers.
/// Thread-safe with interior mutability via RwLock.
pub struct JwksCache {
    /// Map from JWKS URL to cached keys
    cache: RwLock<HashMap<String, CachedJwks>>,
    /// HTTP client for fetching JWKS
    client: reqwest::Client,
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksCache {
    /// Create a new JWKS cache.
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Get a public key for a given JWKS URL and key ID.
    /// Fetches and caches the JWKS if not present or stale.
    ///
    /// On fetch failure, retries with exponential backoff. If all retries fail
    /// and we have stale (but not expired) cached keys, uses those as fallback.
    pub async fn get_key(&self, jwks_url: &str, kid: &str) -> Result<RS256PublicKey> {
        // Try to get from fresh cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(jwks_url)
                && !cached.is_stale()
            {
                if let Some(key) = cached.keys.get(kid) {
                    return Ok(key.clone());
                }
                // Key ID not found in cached JWKS - don't refresh, just error
                return Err(AppError::JwtValidationFailed(format!(
                    "Key ID '{}' not found in JWKS",
                    kid
                )));
            }
        }

        // Cache miss or stale - fetch fresh JWKS with retry
        match self.fetch_jwks_with_retry(jwks_url).await {
            Ok(keys) => {
                // Get the key we need (before moving keys into cache)
                let key = keys.get(kid).cloned().ok_or_else(|| {
                    AppError::JwtValidationFailed(format!("Key ID '{}' not found in JWKS", kid))
                })?;

                // Update cache
                {
                    let mut cache = self.cache.write().unwrap();
                    cache.insert(
                        jwks_url.to_string(),
                        CachedJwks {
                            keys,
                            fetched_at: Instant::now(),
                        },
                    );
                }

                Ok(key)
            }
            Err(fetch_error) => {
                // Fetch failed after retries - try stale cache fallback
                let cache = self.cache.read().unwrap();
                if let Some(cached) = cache.get(jwks_url)
                    && !cached.is_expired()
                    && let Some(key) = cached.keys.get(kid)
                {
                    tracing::warn!(
                        jwks_url = %jwks_url,
                        kid = %kid,
                        cache_age_secs = ?cached.fetched_at.elapsed().as_secs(),
                        "JWKS fetch failed, using stale cached key as fallback"
                    );
                    return Ok(key.clone());
                }

                // No usable fallback - propagate the original error
                Err(fetch_error)
            }
        }
    }

    /// Fetch JWKS with retry and exponential backoff.
    async fn fetch_jwks_with_retry(
        &self,
        url: &str,
    ) -> Result<HashMap<String, RS256PublicKey>> {
        let mut last_error = None;

        for attempt in 0..FETCH_RETRY_ATTEMPTS {
            if attempt > 0 {
                let delay_ms = FETCH_RETRY_BASE_DELAY_MS * 2_u64.pow(attempt - 1);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                tracing::debug!(
                    url = %url,
                    attempt = attempt + 1,
                    delay_ms = delay_ms,
                    "Retrying JWKS fetch"
                );
            }

            match self.fetch_jwks(url).await {
                Ok(keys) => return Ok(keys),
                Err(e) => {
                    tracing::warn!(
                        url = %url,
                        attempt = attempt + 1,
                        error = %e,
                        "JWKS fetch attempt failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            AppError::JwksFetchFailed("All retry attempts exhausted".to_string())
        }))
    }

    /// Fetch JWKS from a URL and parse the keys.
    async fn fetch_jwks(&self, url: &str) -> Result<HashMap<String, RS256PublicKey>> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| AppError::JwksFetchFailed(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::JwksFetchFailed(format!(
                "HTTP {} from JWKS endpoint",
                response.status()
            )));
        }

        let jwks: JwksResponse = response
            .json()
            .await
            .map_err(|e| AppError::JwksFetchFailed(format!("Failed to parse JWKS JSON: {}", e)))?;

        let mut keys = HashMap::new();

        for jwk in jwks.keys {
            // Only process RSA keys with RS256 algorithm (or no algorithm specified)
            if jwk.kty != "RSA" {
                continue;
            }
            if let Some(ref alg) = jwk.alg
                && alg != "RS256"
            {
                continue;
            }

            // Skip keys without a key ID
            let kid = match jwk.kid {
                Some(ref k) => k.clone(),
                None => continue,
            };

            // Parse the RSA public key from n and e components
            match parse_rsa_public_key(&jwk.n, &jwk.e) {
                Ok(public_key) => {
                    keys.insert(kid, public_key);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse JWK with kid '{}': {}",
                        jwk.kid.as_deref().unwrap_or("unknown"),
                        e
                    );
                }
            }
        }

        if keys.is_empty() {
            return Err(AppError::JwksFetchFailed(
                "No valid RS256 keys found in JWKS".to_string(),
            ));
        }

        Ok(keys)
    }
}

/// JWKS response structure (RFC 7517)
#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

/// Individual JWK structure (RFC 7517)
#[derive(Debug, Deserialize)]
struct Jwk {
    /// Key type (e.g., "RSA")
    kty: String,
    /// Key ID
    kid: Option<String>,
    /// Algorithm (e.g., "RS256")
    alg: Option<String>,
    /// RSA modulus (base64url encoded)
    #[serde(default)]
    n: String,
    /// RSA exponent (base64url encoded)
    #[serde(default)]
    e: String,
}

/// Parse an RSA public key from base64url-encoded n and e components.
fn parse_rsa_public_key(n_b64: &str, e_b64: &str) -> Result<RS256PublicKey> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Decode base64url components
    let n_bytes = URL_SAFE_NO_PAD
        .decode(n_b64)
        .map_err(|e| AppError::JwksFetchFailed(format!("Invalid base64url for 'n': {}", e)))?;
    let e_bytes = URL_SAFE_NO_PAD
        .decode(e_b64)
        .map_err(|e| AppError::JwksFetchFailed(format!("Invalid base64url for 'e': {}", e)))?;

    // Use jwt-simple's built-in RSA key construction from components
    RS256PublicKey::from_components(&n_bytes, &e_bytes)
        .map_err(|e| AppError::JwksFetchFailed(format!("Failed to parse RSA key: {}", e)))
}

impl JwksCache {
    /// Seed the cache with keys for testing purposes.
    /// The `age` parameter controls how old the cached entry appears.
    #[cfg(test)]
    pub fn seed_cache_for_testing(
        &self,
        url: &str,
        keys: HashMap<String, RS256PublicKey>,
        age: Duration,
    ) {
        let mut cache = self.cache.write().unwrap();
        cache.insert(
            url.to_string(),
            CachedJwks {
                keys,
                fetched_at: Instant::now() - age,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_stale_detection() {
        // This test just verifies the stale detection logic works
        let cached = CachedJwks {
            keys: HashMap::new(),
            fetched_at: Instant::now(),
        };
        assert!(!cached.is_stale());
        assert!(!cached.is_expired());
    }

    #[test]
    fn test_cache_expiry_detection() {
        // Test that expired detection works (for fallback logic)
        let cached = CachedJwks {
            keys: HashMap::new(),
            fetched_at: Instant::now() - MAX_STALE_DURATION - Duration::from_secs(1),
        };
        assert!(cached.is_stale());
        assert!(cached.is_expired());
    }

    #[test]
    fn test_stale_but_not_expired() {
        // Cache that is stale (>1 hour) but not expired (<24 hours)
        // This is the window where fallback should work
        let cached = CachedJwks {
            keys: HashMap::new(),
            fetched_at: Instant::now() - CACHE_DURATION - Duration::from_secs(3600), // 2 hours old
        };
        assert!(cached.is_stale());
        assert!(!cached.is_expired());
    }

    #[test]
    fn test_retry_constants_are_reasonable() {
        // Sanity check that retry settings are reasonable
        assert!(FETCH_RETRY_ATTEMPTS >= 2, "Should retry at least once");
        assert!(FETCH_RETRY_ATTEMPTS <= 5, "Too many retries would be slow");
        assert!(
            FETCH_RETRY_BASE_DELAY_MS >= 50,
            "Base delay should be at least 50ms"
        );
        assert!(
            FETCH_RETRY_BASE_DELAY_MS <= 500,
            "Base delay over 500ms is too slow"
        );

        // Calculate max total delay: base * (2^0 + 2^1 + ... + 2^(n-2))
        // For 3 attempts with 100ms base: 0 + 100 + 200 = 300ms max
        let max_total_delay: u64 = (1..FETCH_RETRY_ATTEMPTS)
            .map(|i| FETCH_RETRY_BASE_DELAY_MS * 2_u64.pow(i - 1))
            .sum();
        assert!(
            max_total_delay < 2000,
            "Total retry delay should be under 2 seconds"
        );
    }
}
