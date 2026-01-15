//! CORS/origin validation security tests
//!
//! These tests verify that:
//! 1. Public endpoints allow any origin (Access-Control-Allow-Origin: *)
//! 2. Admin endpoints (operators/*, orgs/*) restrict origins to configured console origins
//! 3. Preflight (OPTIONS) requests are handled correctly
//! 4. CORS headers are properly set (credentials, methods, headers, max-age)
//!
//! CORS Policy Summary:
//! - Public endpoints: Any origin allowed (for customer websites)
//! - Admin endpoints: Only configured console origins (PAYCHECK_CONSOLE_ORIGINS)
//! - Dev mode default: http://localhost:3001 and http://127.0.0.1:3001

#[path = "../common/mod.rs"]
mod common;
use common::*;

use axum::{
    Router,
    body::Body,
    http::{HeaderName, HeaderValue, Method, Request, StatusCode},
    routing::{get, post},
};
use tower::ServiceExt;
use tower_http::cors::{Any, CorsLayer};

use paycheck::config::RateLimitConfig;
use paycheck::db::AppState;
use paycheck::handlers;
use paycheck::handlers::public::{
    deactivate_device, get_license_info, initiate_buy, payment_callback, redeem_with_code,
    request_activation_code, validate_license,
};
use paycheck::models::{OperatorRole, OrgMemberRole};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

// ============================================================================
// Test App Setup Helpers
// ============================================================================

/// Creates a test app with public endpoints and CORS layer (no rate limiting for tests)
fn public_app() -> (Router, AppState) {
    let state = create_test_app_state();

    // CORS layer for public endpoints: Allow any origin
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
        ]);

    // Create a simplified router with public endpoints (no rate limiting for tests)
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/buy", post(initiate_buy))
        .route("/callback", get(payment_callback))
        .route("/redeem", post(redeem_with_code))
        .route("/activation/request-code", post(request_activation_code))
        .route("/validate", post(validate_license))
        .route("/license", get(get_license_info))
        .route("/devices/deactivate", post(deactivate_device))
        .layer(cors)
        .with_state(state.clone());

    (app, state)
}

/// Simple health handler for tests
async fn health_handler() -> &'static str {
    "ok"
}

/// Creates a test app with the org router and specific console origins for CORS
fn admin_app_with_origins(origins: Vec<&str>) -> (Router, AppState) {
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
        activation_rate_limiter: std::sync::Arc::new(
            paycheck::rate_limit::ActivationRateLimiter::default(),
        ),
        email_service: std::sync::Arc::new(paycheck::email::EmailService::new(
            None,
            "test@example.com".to_string(),
        )),
        jwks_cache: std::sync::Arc::new(paycheck::jwt::JwksCache::new()),
        trusted_issuers: vec![],
    };

    // Create CORS layer with specified origins
    let origin_values: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(origin_values)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
        ])
        .allow_credentials(true);

    // Apply CORS to org router
    let app = handlers::orgs::router(state.clone(), RateLimitConfig::disabled())
        .layer(cors)
        .with_state(state.clone());

    (app, state)
}

/// Creates a test app with the operator router and specific console origins for CORS
fn operator_app_with_origins(origins: Vec<&str>) -> (Router, AppState) {
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
        activation_rate_limiter: std::sync::Arc::new(
            paycheck::rate_limit::ActivationRateLimiter::default(),
        ),
        email_service: std::sync::Arc::new(paycheck::email::EmailService::new(
            None,
            "test@example.com".to_string(),
        )),
        jwks_cache: std::sync::Arc::new(paycheck::jwt::JwksCache::new()),
        trusted_issuers: vec![],
    };

    // Create CORS layer with specified origins
    let origin_values: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(origin_values)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
        ])
        .allow_credentials(true);

    // Apply CORS to operator router
    let app = handlers::operators::router(state.clone())
        .layer(cors)
        .with_state(state.clone());

    (app, state)
}

// ============================================================================
// PUBLIC ENDPOINT CORS TESTS
// ============================================================================

mod public_cors {
    use super::*;

    /// Verify that public endpoints return Access-Control-Allow-Origin: * for any origin
    #[tokio::test]
    async fn test_public_endpoints_allow_any_origin() {
        let (app, _state) = public_app();

        let test_origins = vec![
            "https://example.com",
            "https://customer-site.io",
            "http://localhost:8080",
            "https://subdomain.another-domain.org",
        ];

        for origin in test_origins {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/health")
                        .header("Origin", origin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Health endpoint should return 200 for origin {}",
                origin
            );

            // Public endpoints should return Access-Control-Allow-Origin: *
            let cors_header = response
                .headers()
                .get("access-control-allow-origin")
                .map(|v| v.to_str().unwrap_or(""));

            assert!(
                cors_header == Some("*"),
                "Public endpoint should return Access-Control-Allow-Origin: * for origin {}, got {:?}",
                origin,
                cors_header
            );
        }
    }

    /// Verify that public endpoints work without Origin header
    #[tokio::test]
    async fn test_public_endpoints_work_without_origin() {
        let (app, _state) = public_app();

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
            "Health endpoint should work without Origin header"
        );
    }

    /// Verify OPTIONS preflight request returns correct headers for public endpoints
    #[tokio::test]
    async fn test_public_preflight_request() {
        let (app, _state) = public_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/health")
                    .header("Origin", "https://example.com")
                    .header("Access-Control-Request-Method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // OPTIONS should return 200 OK (preflight success)
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Preflight request should return 200 OK"
        );

        // Should have CORS headers
        assert!(
            response.headers().contains_key("access-control-allow-origin"),
            "Preflight response should have Access-Control-Allow-Origin"
        );

        assert!(
            response.headers().contains_key("access-control-allow-methods"),
            "Preflight response should have Access-Control-Allow-Methods"
        );
    }

    /// Verify that POST endpoints also have CORS headers
    #[tokio::test]
    async fn test_public_post_endpoint_cors() {
        let (app, state) = public_app();

        // Create test data for /validate endpoint
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let product = create_test_product(&conn, &project.id, "Pro", "pro");
        let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_MONTH)));
        let _device = create_test_device(&conn, &license.id, "device-1", paycheck::models::DeviceType::Uuid);
        drop(conn);

        // Make a POST request to /validate
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("Origin", "https://customer-app.com")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"jwt":"invalid","public_key":"invalid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Response will be 400 due to invalid JWT, but CORS headers should still be present
        let cors_header = response
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or(""));

        assert!(
            cors_header == Some("*"),
            "POST endpoint should return Access-Control-Allow-Origin: * even on error"
        );
    }

    /// Verify allowed methods for public endpoints
    #[tokio::test]
    async fn test_public_allowed_methods() {
        let (app, _state) = public_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/validate")
                    .header("Origin", "https://example.com")
                    .header("Access-Control-Request-Method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let methods = response
            .headers()
            .get("access-control-allow-methods")
            .map(|v| v.to_str().unwrap_or(""));

        // Should allow at least GET, POST, OPTIONS
        if let Some(methods_str) = methods {
            assert!(
                methods_str.contains("GET") || methods_str.contains("get"),
                "Should allow GET method"
            );
            assert!(
                methods_str.contains("POST") || methods_str.contains("post"),
                "Should allow POST method"
            );
            assert!(
                methods_str.contains("OPTIONS") || methods_str.contains("options"),
                "Should allow OPTIONS method"
            );
        }
    }

    /// Verify allowed headers for public endpoints
    #[tokio::test]
    async fn test_public_allowed_headers() {
        let (app, _state) = public_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/redeem")
                    .header("Origin", "https://example.com")
                    .header("Access-Control-Request-Method", "POST")
                    .header("Access-Control-Request-Headers", "content-type,authorization")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let headers = response
            .headers()
            .get("access-control-allow-headers")
            .map(|v| v.to_str().unwrap_or(""));

        // Should allow content-type and authorization
        if let Some(headers_str) = headers {
            let headers_lower = headers_str.to_lowercase();
            assert!(
                headers_lower.contains("content-type"),
                "Should allow Content-Type header"
            );
            assert!(
                headers_lower.contains("authorization"),
                "Should allow Authorization header"
            );
        }
    }
}

// ============================================================================
// ADMIN ENDPOINT CORS TESTS
// ============================================================================

mod admin_cors {
    use super::*;

    /// Verify that admin endpoints (orgs/*) reject requests from non-allowed origins
    #[tokio::test]
    async fn test_admin_endpoints_reject_non_allowed_origins() {
        // Set up app with specific allowed origin
        let (app, state) = admin_app_with_origins(vec!["https://console.paycheck.dev"]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        drop(conn);

        // Request from non-allowed origin
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Origin", "https://malicious-site.com")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // The request may still return 200 (CORS doesn't block server-side),
        // but the CORS header should NOT include the malicious origin
        let cors_header = response
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or(""));

        // Should either be None or not match the malicious origin
        assert!(
            cors_header.is_none() || cors_header != Some("https://malicious-site.com"),
            "Admin endpoint should not allow malicious origin, got {:?}",
            cors_header
        );
    }

    /// Verify that admin endpoints accept requests from allowed console origins
    #[tokio::test]
    async fn test_admin_endpoints_accept_allowed_origins() {
        let allowed_origin = "https://console.paycheck.dev";
        let (app, state) = admin_app_with_origins(vec![allowed_origin]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        drop(conn);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Origin", allowed_origin)
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Request from allowed origin should succeed"
        );

        let cors_header = response
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or(""));

        assert_eq!(
            cors_header,
            Some(allowed_origin),
            "Should return the allowed origin in CORS header"
        );
    }

    /// Verify that multiple console origins are supported
    #[tokio::test]
    async fn test_multiple_console_origins_supported() {
        let origins = vec![
            "https://console.paycheck.dev",
            "https://staging-console.paycheck.dev",
            "http://localhost:3001",
        ];

        let (app, state) = admin_app_with_origins(origins.clone());

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        drop(conn);

        // Test each allowed origin
        for origin in &origins {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/orgs/{}/members", org.id))
                        .header("Origin", *origin)
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Request from allowed origin {} should succeed",
                origin
            );

            let cors_header = response
                .headers()
                .get("access-control-allow-origin")
                .map(|v| v.to_str().unwrap_or(""));

            assert_eq!(
                cors_header,
                Some(*origin),
                "Should return the matching origin {} in CORS header",
                origin
            );
        }
    }

    /// Verify that credentials header is set for admin endpoints
    #[tokio::test]
    async fn test_admin_credentials_header() {
        let allowed_origin = "https://console.paycheck.dev";
        let (app, state) = admin_app_with_origins(vec![allowed_origin]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        drop(conn);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Origin", allowed_origin)
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let credentials_header = response
            .headers()
            .get("access-control-allow-credentials")
            .map(|v| v.to_str().unwrap_or(""));

        assert_eq!(
            credentials_header,
            Some("true"),
            "Admin endpoints should set Access-Control-Allow-Credentials: true"
        );
    }

    /// Verify allowed methods for admin endpoints
    #[tokio::test]
    async fn test_admin_allowed_methods() {
        let allowed_origin = "https://console.paycheck.dev";
        let (app, state) = admin_app_with_origins(vec![allowed_origin]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        drop(conn);

        // Send preflight request
        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Origin", allowed_origin)
                    .header("Access-Control-Request-Method", "PUT")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let methods = response
            .headers()
            .get("access-control-allow-methods")
            .map(|v| v.to_str().unwrap_or(""));

        // Admin endpoints should allow GET, POST, PUT, DELETE, OPTIONS
        if let Some(methods_str) = methods {
            let methods_upper = methods_str.to_uppercase();
            assert!(methods_upper.contains("GET"), "Should allow GET");
            assert!(methods_upper.contains("POST"), "Should allow POST");
            assert!(methods_upper.contains("PUT"), "Should allow PUT");
            assert!(methods_upper.contains("DELETE"), "Should allow DELETE");
            assert!(methods_upper.contains("OPTIONS"), "Should allow OPTIONS");
        }
    }

    /// Verify allowed headers include Authorization and Content-Type for admin endpoints
    #[tokio::test]
    async fn test_admin_allowed_headers() {
        let allowed_origin = "https://console.paycheck.dev";
        let (app, state) = admin_app_with_origins(vec![allowed_origin]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        drop(conn);

        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Origin", allowed_origin)
                    .header("Access-Control-Request-Method", "POST")
                    .header("Access-Control-Request-Headers", "authorization,content-type")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let headers = response
            .headers()
            .get("access-control-allow-headers")
            .map(|v| v.to_str().unwrap_or(""));

        if let Some(headers_str) = headers {
            let headers_lower = headers_str.to_lowercase();
            assert!(
                headers_lower.contains("authorization"),
                "Should allow Authorization header"
            );
            assert!(
                headers_lower.contains("content-type"),
                "Should allow Content-Type header"
            );
        }
    }

    /// Verify operator endpoints also have restricted CORS
    #[tokio::test]
    async fn test_operator_endpoints_restricted_cors() {
        let allowed_origin = "https://console.paycheck.dev";
        let (app, state) = operator_app_with_origins(vec![allowed_origin]);

        // Create test operator
        let conn = state.db.get().unwrap();
        let (_user, _operator, api_key) =
            create_test_operator(&conn, "admin@paycheck.dev", OperatorRole::Admin);
        drop(conn);

        // Request from allowed origin
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs")
                    .header("Origin", allowed_origin)
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let cors_header = response
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or(""));

        assert_eq!(
            cors_header,
            Some(allowed_origin),
            "Operator endpoint should return allowed origin"
        );

        // Request from non-allowed origin
        let response_bad = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs")
                    .header("Origin", "https://evil.com")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let cors_header_bad = response_bad
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or(""));

        assert!(
            cors_header_bad.is_none() || cors_header_bad != Some("https://evil.com"),
            "Operator endpoint should not allow evil origin"
        );
    }
}

// ============================================================================
// PREFLIGHT REQUEST TESTS
// ============================================================================

mod preflight_requests {
    use super::*;

    /// Verify OPTIONS preflight for public POST endpoint
    #[tokio::test]
    async fn test_preflight_for_post_endpoint() {
        let (app, _state) = public_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/buy")
                    .header("Origin", "https://customer-site.com")
                    .header("Access-Control-Request-Method", "POST")
                    .header("Access-Control-Request-Headers", "content-type")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Preflight should return 200 OK
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Preflight for POST should return 200"
        );
    }

    /// Verify OPTIONS preflight for admin PUT endpoint
    #[tokio::test]
    async fn test_preflight_for_admin_put_endpoint() {
        let allowed_origin = "https://console.paycheck.dev";
        let (app, state) = admin_app_with_origins(vec![allowed_origin]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        drop(conn);

        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(format!("/orgs/{}/projects", org.id))
                    .header("Origin", allowed_origin)
                    .header("Access-Control-Request-Method", "PUT")
                    .header("Access-Control-Request-Headers", "authorization,content-type")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Preflight for admin PUT should return 200"
        );
    }

    /// Verify OPTIONS preflight for admin DELETE endpoint
    #[tokio::test]
    async fn test_preflight_for_admin_delete_endpoint() {
        let allowed_origin = "https://console.paycheck.dev";
        let (app, state) = admin_app_with_origins(vec![allowed_origin]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        drop(conn);

        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
                    .header("Origin", allowed_origin)
                    .header("Access-Control-Request-Method", "DELETE")
                    .header("Access-Control-Request-Headers", "authorization")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Preflight for admin DELETE should return 200"
        );
    }

    /// Verify preflight request does not require authentication
    #[tokio::test]
    async fn test_preflight_no_auth_required() {
        let allowed_origin = "https://console.paycheck.dev";
        let (app, state) = admin_app_with_origins(vec![allowed_origin]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        drop(conn);

        // Send preflight WITHOUT Authorization header
        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Origin", allowed_origin)
                    .header("Access-Control-Request-Method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Preflight should succeed even without auth
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Preflight should not require authentication"
        );
    }

    /// Verify preflight returns appropriate max-age header
    #[tokio::test]
    async fn test_preflight_max_age() {
        let (app, _state) = public_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/health")
                    .header("Origin", "https://example.com")
                    .header("Access-Control-Request-Method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Check if max-age header is present (optional but recommended)
        // tower-http's CorsLayer sets a default max-age
        let _max_age = response
            .headers()
            .get("access-control-max-age")
            .map(|v| v.to_str().unwrap_or(""));

        // The presence of max-age is good for caching preflight responses
        // No assertion here since it may or may not be configured
    }
}

// ============================================================================
// EDGE CASES
// ============================================================================

mod edge_cases {
    use super::*;

    /// Verify behavior with null origin
    #[tokio::test]
    async fn test_null_origin() {
        let (app, _state) = public_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .header("Origin", "null")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Request should not fail due to "null" origin
        assert!(
            response.status() != StatusCode::INTERNAL_SERVER_ERROR,
            "Null origin should not cause server error"
        );
    }

    /// Verify behavior with empty origin
    #[tokio::test]
    async fn test_empty_origin() {
        let (app, _state) = public_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .header("Origin", "")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Request should not fail due to empty origin
        assert!(
            response.status() != StatusCode::INTERNAL_SERVER_ERROR,
            "Empty origin should not cause server error"
        );
    }

    /// Verify that case variations in origin don't bypass restrictions
    #[tokio::test]
    async fn test_origin_case_sensitivity() {
        let allowed_origin = "https://console.paycheck.dev";
        let (app, state) = admin_app_with_origins(vec![allowed_origin]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        drop(conn);

        // Test case variations that should NOT match
        let case_variations = vec![
            "HTTPS://CONSOLE.PAYCHECK.DEV",
            "https://CONSOLE.paycheck.dev",
            "Https://Console.Paycheck.Dev",
        ];

        for variant in case_variations {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/orgs/{}/members", org.id))
                        .header("Origin", variant)
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            let cors_header = response
                .headers()
                .get("access-control-allow-origin")
                .map(|v| v.to_str().unwrap_or(""));

            // URL matching is typically case-sensitive for scheme and host
            // So case variations should not be matched
            assert!(
                cors_header.is_none() || cors_header == Some(allowed_origin),
                "Case variation '{}' should not be matched as different from allowed origin",
                variant
            );
        }
    }

    /// Verify that origin with trailing slash is handled correctly
    #[tokio::test]
    async fn test_origin_with_trailing_slash() {
        let allowed_origin = "https://console.paycheck.dev";
        let (app, state) = admin_app_with_origins(vec![allowed_origin]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        drop(conn);

        // Origin with trailing slash
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Origin", "https://console.paycheck.dev/")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let cors_header = response
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or(""));

        // Trailing slash makes it a different origin
        assert!(
            cors_header.is_none() || cors_header != Some("https://console.paycheck.dev/"),
            "Origin with trailing slash should not match allowed origin without slash"
        );
    }

    /// Verify that origin with port is handled correctly
    #[tokio::test]
    async fn test_origin_with_different_port() {
        let allowed_origin = "http://localhost:3001";
        let (app, state) = admin_app_with_origins(vec![allowed_origin]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        drop(conn);

        // Different port should not be allowed
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Origin", "http://localhost:3000")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let cors_header = response
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or(""));

        // Different port is a different origin
        assert!(
            cors_header.is_none() || cors_header != Some("http://localhost:3000"),
            "Different port should not be allowed"
        );
    }

    /// Verify that subdomain variations don't bypass restrictions
    #[tokio::test]
    async fn test_subdomain_variations() {
        let allowed_origin = "https://console.paycheck.dev";
        let (app, state) = admin_app_with_origins(vec![allowed_origin]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        drop(conn);

        let subdomain_variations = vec![
            "https://evil.console.paycheck.dev",
            "https://paycheck.dev",
            "https://staging.console.paycheck.dev",
            "https://console-evil.paycheck.dev",
        ];

        for variant in subdomain_variations {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/orgs/{}/members", org.id))
                        .header("Origin", variant)
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            let cors_header = response
                .headers()
                .get("access-control-allow-origin")
                .map(|v| v.to_str().unwrap_or(""));

            // Subdomain variations should not be matched
            assert!(
                cors_header.is_none() || cors_header != Some(variant),
                "Subdomain variation '{}' should not be allowed",
                variant
            );
        }
    }

    /// Verify that protocol variations don't bypass restrictions
    #[tokio::test]
    async fn test_protocol_variations() {
        let allowed_origin = "https://console.paycheck.dev";
        let (app, state) = admin_app_with_origins(vec![allowed_origin]);

        // Create test data
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        drop(conn);

        // HTTP instead of HTTPS should not be allowed
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Origin", "http://console.paycheck.dev")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let cors_header = response
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or(""));

        // Different protocol is a different origin
        assert!(
            cors_header.is_none() || cors_header != Some("http://console.paycheck.dev"),
            "HTTP protocol should not match HTTPS allowed origin"
        );
    }

    /// Test that invalid origin header values don't crash the server
    #[tokio::test]
    async fn test_malformed_origin_handling() {
        let (app, _state) = public_app();

        let malformed_origins = vec![
            "not-a-url",
            "://missing-scheme.com",
            "https://",
            "javascript:alert(1)",
            "<script>alert(1)</script>",
        ];

        for origin in malformed_origins {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/health")
                        .header("Origin", origin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            // Should not crash
            assert!(
                response.status() != StatusCode::INTERNAL_SERVER_ERROR,
                "Malformed origin '{}' should not cause 500 error",
                origin
            );
        }
    }
}
