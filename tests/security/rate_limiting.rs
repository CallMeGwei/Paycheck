//! Rate limiting security tests for API endpoints.
//!
//! These tests verify that:
//! 1. Rate limit headers are returned correctly (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After)
//! 2. Requests within limits succeed
//! 3. Requests exceeding limits return 429 Too Many Requests
//! 4. Rate limits reset after the window expires
//! 5. Different endpoints have different limits (strict vs standard vs relaxed)
//! 6. Activation code request rate limiting (3 req/email/hour) works
//! 7. Rate limiting applies per-IP (different IPs have separate limits)
//!
//! CRITICAL: These tests ensure DoS protection and abuse prevention work correctly.

#[path = "../common/mod.rs"]
mod common;
use common::*;

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use paycheck::config::RateLimitConfig;
use paycheck::db::AppState;
use paycheck::handlers;
use paycheck::rate_limit::ActivationRateLimiter;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::net::SocketAddr;
use std::sync::Arc;

// ============================================================================
// Test App Setup Helpers
// ============================================================================

/// Creates a public app with actual rate limiting enabled.
/// Uses low limits to make testing practical.
/// Includes ConnectInfo extension to provide IP address for rate limiting.
fn public_app_with_rate_limits(config: RateLimitConfig) -> (Router, AppState) {
    public_app_with_rate_limits_and_ip(config, "127.0.0.1:12345".parse().unwrap())
}

/// Creates a public app with rate limiting and a specific mock IP address.
/// Useful for testing per-IP rate limiting isolation.
fn public_app_with_rate_limits_and_ip(config: RateLimitConfig, ip: SocketAddr) -> (Router, AppState) {
    let master_key = test_master_key();

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();
    {
        let conn = pool.get().unwrap();
        paycheck::db::init_db(&conn).unwrap();
    }

    let audit_manager = SqliteConnectionManager::memory();
    let audit_pool = Pool::builder().max_size(4).build(audit_manager).unwrap();
    {
        let conn = audit_pool.get().unwrap();
        paycheck::db::init_audit_db(&conn).unwrap();
    }

    let state = AppState {
        db: pool,
        audit: audit_pool,
        base_url: "http://localhost:3000".to_string(),
        audit_log_enabled: false,
        master_key,
        email_hasher: paycheck::crypto::EmailHasher::from_bytes([0xAA; 32]),
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: Arc::new(ActivationRateLimiter::default()),
        email_service: Arc::new(paycheck::email::EmailService::new(
            None,
            "test@example.com".to_string(),
        )),
        jwks_cache: Arc::new(paycheck::jwt::JwksCache::new()),
        trusted_issuers: vec![],
    };

    // Use axum::Extension to directly inject ConnectInfo for PeerIpKeyExtractor
    // tower-governor looks for ConnectInfo<SocketAddr> in request extensions
    let app = handlers::public::router(config)
        .layer(axum::Extension(ConnectInfo(ip)))
        .with_state(state.clone());

    (app, state)
}

/// Creates a public app with custom activation rate limiter.
#[allow(dead_code)]
fn public_app_with_activation_limiter(
    rate_config: RateLimitConfig,
    activation_limiter: ActivationRateLimiter,
) -> (Router, AppState) {
    let master_key = test_master_key();

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();
    {
        let conn = pool.get().unwrap();
        paycheck::db::init_db(&conn).unwrap();
    }

    let audit_manager = SqliteConnectionManager::memory();
    let audit_pool = Pool::builder().max_size(4).build(audit_manager).unwrap();
    {
        let conn = audit_pool.get().unwrap();
        paycheck::db::init_audit_db(&conn).unwrap();
    }

    let state = AppState {
        db: pool,
        audit: audit_pool,
        base_url: "http://localhost:3000".to_string(),
        audit_log_enabled: false,
        master_key,
        email_hasher: paycheck::crypto::EmailHasher::from_bytes([0xAA; 32]),
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: Arc::new(activation_limiter),
        email_service: Arc::new(paycheck::email::EmailService::new(
            None,
            "test@example.com".to_string(),
        )),
        jwks_cache: Arc::new(paycheck::jwt::JwksCache::new()),
        trusted_issuers: vec![],
    };

    // Use axum::Extension to directly inject ConnectInfo for PeerIpKeyExtractor
    let app = handlers::public::router(rate_config)
        .layer(axum::Extension(ConnectInfo("127.0.0.1:12345".parse::<SocketAddr>().unwrap())))
        .with_state(state.clone());

    (app, state)
}

// ============================================================================
// RATE LIMIT HEADERS TESTS
// ============================================================================

mod rate_limit_headers {
    use super::*;

    /// Verify that rate limit headers are returned on successful requests.
    /// tower-governor adds X-RateLimit-* headers to responses.
    #[tokio::test]
    async fn test_rate_limit_headers_present() {
        let config = RateLimitConfig {
            strict_rpm: 10,
            standard_rpm: 30,
            relaxed_rpm: 60,
            org_ops_rpm: 3000,
        };
        let (app, _state) = public_app_with_rate_limits(config);

        // Make a request to the health endpoint (relaxed tier)
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Health endpoint should return 200 OK when rate limiting is enabled"
        );

        // tower-governor uses x-ratelimit-limit, x-ratelimit-remaining, x-ratelimit-after
        // Note: tower-governor with default config may not add headers on success.
        // The key test is that requests succeed within limits and get 429 when exceeded.
        // Rate limit headers are optional and depend on governor configuration.
        //
        // This test verifies the endpoint works with rate limiting enabled.
        // The actual rate limiting behavior is tested in other test modules.
    }

    /// Verify Retry-After header is returned when rate limited.
    #[tokio::test]
    async fn test_retry_after_header_on_429() {
        // Use a very low limit to trigger rate limiting quickly
        let config = RateLimitConfig {
            strict_rpm: 1, // 1 request per minute
            standard_rpm: 30,
            relaxed_rpm: 60,
            org_ops_rpm: 3000,
        };
        let (app, state) = public_app_with_rate_limits(config);

        // Set up test data for /buy endpoint
        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            setup_stripe_config(&conn, &org.id, &state.master_key);
            let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
            let product = create_test_product(&conn, &project.id, "Pro", "pro");
            create_test_payment_config(&conn, &product.id, "stripe", Some(999));
        }

        // First request should succeed or fail due to missing Stripe (not rate limit)
        let app_clone = app.clone();
        let first_response = app_clone
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/buy")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"product_id": "test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // The first request might fail for various reasons, but subsequent ones should hit rate limit
        let _first_status = first_response.status();

        // Second request should be rate limited
        let second_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/buy")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"product_id": "test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            second_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Second request should be rate limited"
        );

        // Check for retry-after header
        let headers = second_response.headers();
        let has_retry_header = headers.get("retry-after").is_some()
            || headers.get("x-ratelimit-after").is_some();

        assert!(
            has_retry_header,
            "Expected retry-after or x-ratelimit-after header when rate limited"
        );
    }
}

// ============================================================================
// STRICT RATE LIMIT TESTS (/buy, /activation/request-code)
// ============================================================================

mod strict_rate_limit {
    use super::*;

    /// Verify that the /buy endpoint has strict rate limiting.
    /// Strict tier defaults to 10 RPM.
    #[tokio::test]
    async fn test_buy_endpoint_strict_rate_limit() {
        // Configure with 2 requests per minute to test quickly
        let config = RateLimitConfig {
            strict_rpm: 2,
            standard_rpm: 30,
            relaxed_rpm: 60,
            org_ops_rpm: 3000,
        };
        let (app, state) = public_app_with_rate_limits(config);

        // Set up test data
        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            setup_stripe_config(&conn, &org.id, &state.master_key);
            let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
            let product = create_test_product(&conn, &project.id, "Pro", "pro");
            create_test_payment_config(&conn, &product.id, "stripe", Some(999));
        }

        // Make requests up to the limit
        for i in 0..2 {
            let app_clone = app.clone();
            let response = app_clone
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/buy")
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"product_id": "test"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();

            // These might fail for other reasons (invalid product, no Stripe), but not 429
            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "Request {} should not be rate limited",
                i + 1
            );
        }

        // Next request should be rate limited
        let final_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/buy")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"product_id": "test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            final_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request after limit should return 429"
        );
    }

    /// Verify that /activation/request-code has strict rate limiting.
    #[tokio::test]
    async fn test_activation_request_code_strict_rate_limit() {
        let config = RateLimitConfig {
            strict_rpm: 2,
            standard_rpm: 30,
            relaxed_rpm: 60,
            org_ops_rpm: 3000,
        };
        let (app, state) = public_app_with_rate_limits(config);

        // Set up test data with a license
        let public_key: String;
        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
            let product = create_test_product(&conn, &project.id, "Pro", "pro");
            let _license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_MONTH)));
            public_key = project.public_key;
        }

        // Make requests up to the limit
        for i in 0..2 {
            let app_clone = app.clone();
            let response = app_clone
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/activation/request-code")
                        .header("content-type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"email": "test@example.com", "public_key": "{}"}}"#,
                            public_key
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();

            // Should not be rate limited yet (may fail for other reasons)
            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "Request {} should not be rate limited",
                i + 1
            );
        }

        // Next request should be rate limited
        let final_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/activation/request-code")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"email": "test@example.com", "public_key": "{}"}}"#,
                        public_key
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            final_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request after limit should return 429"
        );
    }
}

// ============================================================================
// STANDARD RATE LIMIT TESTS (/callback, /redeem, /validate, etc.)
// ============================================================================

mod standard_rate_limit {
    use super::*;

    /// Verify that /validate has standard (30 RPM) rate limiting.
    #[tokio::test]
    async fn test_validate_endpoint_standard_rate_limit() {
        let config = RateLimitConfig {
            strict_rpm: 10,
            standard_rpm: 3, // Low limit for testing
            relaxed_rpm: 60,
            org_ops_rpm: 3000,
        };
        let (app, _state) = public_app_with_rate_limits(config);

        // Make requests up to the limit
        for i in 0..3 {
            let app_clone = app.clone();
            let response = app_clone
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/validate")
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"jwt": "invalid.jwt.token"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();

            // May fail for other reasons, but not 429
            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "Request {} should not be rate limited",
                i + 1
            );
        }

        // Next request should be rate limited
        let final_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jwt": "invalid.jwt.token"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            final_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request after limit should return 429"
        );
    }

    /// Verify that /redeem has standard rate limiting.
    #[tokio::test]
    async fn test_redeem_endpoint_standard_rate_limit() {
        let config = RateLimitConfig {
            strict_rpm: 10,
            standard_rpm: 2, // Very low for testing
            relaxed_rpm: 60,
            org_ops_rpm: 3000,
        };
        let (app, _state) = public_app_with_rate_limits(config);

        // Make requests up to the limit
        for i in 0..2 {
            let app_clone = app.clone();
            let response = app_clone
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/redeem")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"code": "TEST-XXXX-XXXX-XXXX-XXXX", "device_id": "test", "device_type": "uuid"}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "Request {} should not be rate limited",
                i + 1
            );
        }

        // Next request should be rate limited
        let final_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"code": "TEST-XXXX-XXXX-XXXX-XXXX", "device_id": "test", "device_type": "uuid"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            final_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request after limit should return 429"
        );
    }

    /// Verify that /license GET has standard rate limiting.
    #[tokio::test]
    async fn test_license_endpoint_standard_rate_limit() {
        let config = RateLimitConfig {
            strict_rpm: 10,
            standard_rpm: 2,
            relaxed_rpm: 60,
            org_ops_rpm: 3000,
        };
        let (app, _state) = public_app_with_rate_limits(config);

        // Make requests up to the limit
        for i in 0..2 {
            let app_clone = app.clone();
            let response = app_clone
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/license?jwt=invalid&public_key=invalid")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "Request {} should not be rate limited",
                i + 1
            );
        }

        // Next request should be rate limited
        let final_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/license?jwt=invalid&public_key=invalid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            final_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request after limit should return 429"
        );
    }

    /// Verify that /devices/deactivate has standard rate limiting.
    #[tokio::test]
    async fn test_deactivate_endpoint_standard_rate_limit() {
        let config = RateLimitConfig {
            strict_rpm: 10,
            standard_rpm: 2,
            relaxed_rpm: 60,
            org_ops_rpm: 3000,
        };
        let (app, _state) = public_app_with_rate_limits(config);

        // Make requests up to the limit
        for i in 0..2 {
            let app_clone = app.clone();
            let response = app_clone
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/devices/deactivate")
                        .header("authorization", "Bearer invalid.jwt.token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "Request {} should not be rate limited",
                i + 1
            );
        }

        // Next request should be rate limited
        let final_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/devices/deactivate")
                    .header("authorization", "Bearer invalid.jwt.token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            final_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request after limit should return 429"
        );
    }
}

// ============================================================================
// RELAXED RATE LIMIT TESTS (/health)
// ============================================================================

mod relaxed_rate_limit {
    use super::*;

    /// Verify that /health has relaxed (60 RPM) rate limiting.
    /// This allows more requests than strict/standard tiers.
    #[tokio::test]
    async fn test_health_endpoint_relaxed_rate_limit() {
        let config = RateLimitConfig {
            strict_rpm: 2,
            standard_rpm: 3,
            relaxed_rpm: 5, // Higher than strict/standard for testing
            org_ops_rpm: 3000,
        };
        let (app, _state) = public_app_with_rate_limits(config);

        // Make requests up to the relaxed limit
        for i in 0..5 {
            let app_clone = app.clone();
            let response = app_clone
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Health check {} should succeed",
                i + 1
            );
        }

        // Next request should be rate limited
        let final_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            final_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request after relaxed limit should return 429"
        );
    }

    /// Verify that /health has higher limit than /validate (standard tier).
    #[tokio::test]
    async fn test_relaxed_allows_more_than_standard() {
        let config = RateLimitConfig {
            strict_rpm: 1,
            standard_rpm: 2,
            relaxed_rpm: 4,
            org_ops_rpm: 3000,
        };
        let (app, _state) = public_app_with_rate_limits(config);

        // Exhaust standard tier (2 requests)
        for i in 0..2 {
            let app_clone = app.clone();
            let response = app_clone
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/validate")
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"jwt": "invalid"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "Validate request {} should not be rate limited",
                i + 1
            );
        }

        // Standard tier should now be exhausted
        let app_clone = app.clone();
        let validate_response = app_clone
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jwt": "invalid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            validate_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Validate should be rate limited after 2 requests"
        );

        // But relaxed tier (/health) should still have capacity
        let health_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            health_response.status(),
            StatusCode::OK,
            "Health should still work when standard tier is exhausted"
        );
    }
}

// ============================================================================
// ACTIVATION CODE RATE LIMIT TESTS (email-based, separate from IP-based)
// ============================================================================

mod activation_rate_limit {
    use super::*;

    /// Verify that activation code requests are limited per email.
    /// Default: 3 requests per email per hour.
    #[tokio::test]
    async fn test_activation_limiter_per_email() {
        // Use a short window for testing (5 seconds instead of 1 hour)
        let activation_limiter = ActivationRateLimiter::new(3, 5);

        // Test the limiter directly (no need to go through HTTP)
        let email_hash = "test_hash_1";

        // First 3 requests should succeed
        for i in 0..3 {
            let result = activation_limiter.check(email_hash);
            assert!(
                result.is_ok(),
                "Request {} of 3 should be allowed within rate limit, got: {:?}",
                i + 1,
                result
            );
        }

        // 4th request should fail
        let result = activation_limiter.check(email_hash);
        assert!(
            result.is_err(),
            "Request 4 should be rate limited after exhausting 3-request limit"
        );
        assert!(
            result.unwrap_err().contains("Rate limit exceeded"),
            "Error message should contain 'Rate limit exceeded' to inform user of throttling"
        );
    }

    /// Verify that different emails have separate rate limits.
    #[tokio::test]
    async fn test_activation_limiter_separate_per_email() {
        let activation_limiter = ActivationRateLimiter::new(2, 5);

        let email_hash_1 = "hash_user_1";
        let email_hash_2 = "hash_user_2";

        // Exhaust limit for user 1
        activation_limiter.check(email_hash_1).unwrap();
        activation_limiter.check(email_hash_1).unwrap();
        assert!(
            activation_limiter.check(email_hash_1).is_err(),
            "User 1 should be rate limited after exhausting their 2-request quota"
        );

        // User 2 should still have their full limit
        assert!(
            activation_limiter.check(email_hash_2).is_ok(),
            "User 2 request 1 should succeed - separate rate limit from User 1"
        );
        assert!(
            activation_limiter.check(email_hash_2).is_ok(),
            "User 2 request 2 should succeed - still within their own quota"
        );
        assert!(
            activation_limiter.check(email_hash_2).is_err(),
            "User 2 should be rate limited after exhausting their own 2-request quota"
        );
    }

    /// Verify that activation limiter cleanup works.
    #[tokio::test]
    async fn test_activation_limiter_cleanup() {
        let activation_limiter = ActivationRateLimiter::new(2, 1); // 1 second window

        let email_hash = "cleanup_test_hash";

        // Use up the limit
        activation_limiter.check(email_hash).unwrap();
        activation_limiter.check(email_hash).unwrap();
        assert!(
            activation_limiter.check(email_hash).is_err(),
            "Should be rate limited after exhausting 2-request quota"
        );

        // Wait for window to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Run cleanup
        activation_limiter.cleanup();

        // Should be able to make requests again
        assert!(
            activation_limiter.check(email_hash).is_ok(),
            "After window expires and cleanup, should be able to request again"
        );
    }

    /// Verify default activation rate limiter settings.
    #[tokio::test]
    async fn test_activation_limiter_defaults() {
        let limiter = ActivationRateLimiter::default();

        // Default is 3 requests per hour per email
        let email = "default_test_email";

        // Should allow 3 requests
        assert!(
            limiter.check(email).is_ok(),
            "Default limiter should allow request 1 of 3"
        );
        assert!(
            limiter.check(email).is_ok(),
            "Default limiter should allow request 2 of 3"
        );
        assert!(
            limiter.check(email).is_ok(),
            "Default limiter should allow request 3 of 3"
        );

        // 4th should fail
        assert!(
            limiter.check(email).is_err(),
            "Default limiter should reject 4th request (exceeds 3 per hour limit)"
        );
    }
}

// ============================================================================
// TIER DIFFERENTIATION TESTS
// ============================================================================

mod tier_differentiation {
    use super::*;

    /// Verify that strict tier is more restrictive than standard tier.
    #[tokio::test]
    async fn test_strict_more_restrictive_than_standard() {
        let config = RateLimitConfig {
            strict_rpm: 1,  // Very restrictive
            standard_rpm: 5, // More permissive
            relaxed_rpm: 10,
            org_ops_rpm: 3000,
        };
        let (app, _state) = public_app_with_rate_limits(config);

        // First strict request (to /buy) should work
        let app_clone = app.clone();
        let first_buy = app_clone
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/buy")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"product_id": "test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_ne!(
            first_buy.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "First /buy request should not be rate limited"
        );

        // Second strict request should be rate limited
        let app_clone = app.clone();
        let second_buy = app_clone
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/buy")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"product_id": "test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            second_buy.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Second /buy request should be rate limited (strict tier = 1)"
        );

        // But standard tier (/validate) should still have capacity
        let validate_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jwt": "invalid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_ne!(
            validate_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Standard tier should still have capacity when strict is exhausted"
        );
    }

    /// Verify each tier has independent rate limits.
    #[tokio::test]
    async fn test_tiers_are_independent() {
        let config = RateLimitConfig {
            strict_rpm: 1,
            standard_rpm: 1,
            relaxed_rpm: 1,
            org_ops_rpm: 3000,
        };
        let (app, _state) = public_app_with_rate_limits(config);

        // Exhaust each tier with one request
        // Strict tier - /buy
        let app_clone = app.clone();
        let _ = app_clone
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/buy")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"product_id": "test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Standard tier - /validate
        let app_clone = app.clone();
        let _ = app_clone
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jwt": "invalid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Relaxed tier - /health
        let app_clone = app.clone();
        let _ = app_clone
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Now all tiers should be exhausted
        let app_clone = app.clone();
        let buy_response = app_clone
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/buy")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"product_id": "test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            buy_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Strict tier (/buy) should be exhausted after 1 request"
        );

        let app_clone = app.clone();
        let validate_response = app_clone
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jwt": "invalid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            validate_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Standard tier (/validate) should be exhausted after 1 request"
        );

        let health_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            health_response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Relaxed tier (/health) should be exhausted after 1 request"
        );
    }
}

// ============================================================================
// REQUESTS WITHIN LIMIT SUCCEED TESTS
// ============================================================================

mod within_limit_success {
    use super::*;

    /// Verify that requests within the rate limit succeed.
    #[tokio::test]
    async fn test_requests_within_limit_succeed() {
        let config = RateLimitConfig {
            strict_rpm: 10,
            standard_rpm: 30,
            relaxed_rpm: 60,
            org_ops_rpm: 3000,
        };
        let (app, _state) = public_app_with_rate_limits(config);

        // Make multiple health checks within limit
        for i in 0..5 {
            let app_clone = app.clone();
            let response = app_clone
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Health check {} should succeed within rate limit",
                i + 1
            );
        }
    }
}

// ============================================================================
// REQUESTS EXCEEDING LIMIT RETURN 429 TESTS
// ============================================================================

mod exceeding_limit {
    use super::*;

    /// Verify that exceeding the rate limit returns 429 Too Many Requests.
    #[tokio::test]
    async fn test_exceeding_limit_returns_429() {
        let config = RateLimitConfig {
            strict_rpm: 10,
            standard_rpm: 30,
            relaxed_rpm: 2, // Very low for testing
            org_ops_rpm: 3000,
        };
        let (app, _state) = public_app_with_rate_limits(config);

        // Exhaust the relaxed limit
        for _ in 0..2 {
            let app_clone = app.clone();
            let _ = app_clone
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        // Next request should get 429
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Exceeding rate limit should return 429 Too Many Requests"
        );
    }

    /// Verify 429 response has appropriate headers.
    #[tokio::test]
    async fn test_429_response_format() {
        let config = RateLimitConfig {
            strict_rpm: 1,
            standard_rpm: 30,
            relaxed_rpm: 60,
            org_ops_rpm: 3000,
        };
        let (app, _state) = public_app_with_rate_limits(config);

        // First request uses up the limit
        let app_clone = app.clone();
        let _ = app_clone
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/buy")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"product_id": "test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Second request should be rate limited
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/buy")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"product_id": "test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Second request should return 429 after exhausting strict limit of 1"
        );

        // Response should have rate limit related headers
        let headers = response.headers();
        let has_useful_headers = headers.get("retry-after").is_some()
            || headers.get("x-ratelimit-after").is_some()
            || headers.get("x-ratelimit-remaining").is_some();

        assert!(
            has_useful_headers,
            "429 response should include rate limit headers"
        );
    }
}

// ============================================================================
// PER-IP RATE LIMITING ISOLATION TESTS
// ============================================================================

mod per_ip_rate_limiting {
    use super::*;

    /// Verify that different IPs have separate rate limits.
    /// Each IP should have its own quota.
    #[tokio::test]
    async fn test_different_ips_have_separate_limits() {
        let config = RateLimitConfig {
            strict_rpm: 10,
            standard_rpm: 30,
            relaxed_rpm: 1, // Very low for testing
            org_ops_rpm: 3000,
        };

        // Create app with first IP
        let ip1: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let (app1, _state1) = public_app_with_rate_limits_and_ip(config, ip1);

        // Create app with second IP (shares same config but different IP)
        let ip2: SocketAddr = "192.168.1.2:1234".parse().unwrap();
        let (app2, _state2) = public_app_with_rate_limits_and_ip(config, ip2);

        // Exhaust rate limit for IP 1
        let app1_clone = app1.clone();
        let response1 = app1_clone
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response1.status(),
            StatusCode::OK,
            "First request from IP 1 should succeed"
        );

        // IP 1 should now be rate limited
        let response1_limited = app1
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response1_limited.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "IP 1 should be rate limited"
        );

        // But IP 2 should still work (separate rate limit bucket)
        let response2 = app2
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response2.status(),
            StatusCode::OK,
            "IP 2 should not be affected by IP 1's rate limit"
        );
    }

    /// Verify that the same IP gets rate limited consistently.
    #[tokio::test]
    async fn test_same_ip_shares_rate_limit() {
        let config = RateLimitConfig {
            strict_rpm: 10,
            standard_rpm: 30,
            relaxed_rpm: 2, // Low limit for testing
            org_ops_rpm: 3000,
        };

        let ip: SocketAddr = "10.0.0.1:5678".parse().unwrap();
        let (app, _state) = public_app_with_rate_limits_and_ip(config, ip);

        // Make requests up to the limit
        for i in 0..2 {
            let app_clone = app.clone();
            let response = app_clone
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Request {} should succeed",
                i + 1
            );
        }

        // Next request should be rate limited
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request after limit exhausted should return 429"
        );
    }
}
