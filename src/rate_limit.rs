//! Rate limiting configuration for public endpoints.
//!
//! Rate limits are applied per-IP address to protect against DoS attacks.
//! Brute force is not a concern due to high-entropy keys (80+ bits).
//!
//! Tiers:
//! - Strict: /buy - external API calls
//! - Standard: /callback, /redeem/*, /validate, /license, /devices/*
//! - Relaxed: /health
//!
//! Configure via environment variables:
//! - RATE_LIMIT_STRICT_RPM (default: 10)
//! - RATE_LIMIT_STANDARD_RPM (default: 30)
//! - RATE_LIMIT_RELAXED_RPM (default: 60)

use std::sync::Arc;
use std::time::Duration;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;

/// Rate limiter layer type alias using governor types directly
pub type RateLimitLayer = GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::NoOpMiddleware<governor::clock::QuantaInstant>,
    axum::body::Body,
>;

/// Creates a rate limiter layer with the specified requests per minute.
fn create_layer(requests_per_minute: u32) -> RateLimitLayer {
    assert!(requests_per_minute > 0, "Rate limit must be greater than 0");

    let period_secs = 60 / requests_per_minute as u64;
    let config = GovernorConfigBuilder::default()
        .period(Duration::from_secs(period_secs.max(1)))
        .burst_size(requests_per_minute)
        .finish()
        .expect("Failed to build rate limiter config");

    GovernorLayer::new(Arc::new(config))
}

/// Creates a rate limiter layer for the strict tier.
/// Used for endpoints that make external API calls (e.g., /buy).
pub fn strict_layer(requests_per_minute: u32) -> RateLimitLayer {
    create_layer(requests_per_minute)
}

/// Creates a rate limiter layer for the standard tier.
/// Used for most public endpoints that do crypto/DB operations.
pub fn standard_layer(requests_per_minute: u32) -> RateLimitLayer {
    create_layer(requests_per_minute)
}

/// Creates a rate limiter layer for the relaxed tier.
/// Used for lightweight endpoints like health checks.
pub fn relaxed_layer(requests_per_minute: u32) -> RateLimitLayer {
    create_layer(requests_per_minute)
}

// ============ Activation Code Rate Limiter ============

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// In-memory rate limiter for activation code requests.
/// Limits by email hash to prevent abuse of /activation/request-code.
pub struct ActivationRateLimiter {
    requests: Mutex<HashMap<String, Vec<Instant>>>,
    max_requests: usize,
    window_secs: u64,
}

impl ActivationRateLimiter {
    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            max_requests,
            window_secs,
        }
    }

    /// Check if a request is allowed for the given email hash.
    /// Returns Ok(()) if allowed, Err with message if rate limited.
    pub fn check(&self, email_hash: &str) -> Result<(), &'static str> {
        let mut map = self.requests.lock().unwrap();
        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(self.window_secs);

        let timestamps = map.entry(email_hash.to_string()).or_default();

        // Remove old entries
        timestamps.retain(|t| *t > cutoff);

        if timestamps.len() >= self.max_requests {
            return Err("Rate limit exceeded. Please try again later.");
        }

        timestamps.push(now);
        Ok(())
    }

    /// Clean up expired entries to prevent memory growth.
    /// Call periodically (e.g., every few minutes).
    pub fn cleanup(&self) {
        let mut map = self.requests.lock().unwrap();
        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(self.window_secs);

        map.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }
}

impl Default for ActivationRateLimiter {
    fn default() -> Self {
        // 3 requests per email per hour
        Self::new(3, 3600)
    }
}
