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
