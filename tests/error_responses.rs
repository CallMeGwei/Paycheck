//! Tests to verify all API errors return consistent JSON responses.
//!
//! These tests ensure our custom extractors properly convert Axum's
//! plain text rejections into JSON error responses.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;

mod common;
use common::*;

/// Helper to create a test router with the API routes
fn test_app() -> Router {
    use axum::routing::{get, post};
    use paycheck::handlers::public::{get_license_info, initiate_buy, validate_license};

    let master_key = test_master_key();

    // Create app state
    use paycheck::db::AppState;
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(1).build(manager).unwrap();
    {
        let conn = pool.get().unwrap();
        paycheck::db::init_db(&conn).unwrap();
    }

    let audit_manager = SqliteConnectionManager::memory();
    let audit_pool = Pool::builder().max_size(1).build(audit_manager).unwrap();
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

    Router::new()
        .route("/buy", post(initiate_buy))
        .route("/validate", get(validate_license))
        .route("/license", get(get_license_info))
        .with_state(state)
}

/// Verify invalid JSON body returns JSON error response
#[tokio::test]
async fn test_invalid_json_body_returns_json_error() {
    let app = test_app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from("{ invalid json }"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Verify response is JSON
    let content_type = response.headers().get("content-type").unwrap();
    assert!(content_type.to_str().unwrap().contains("application/json"));

    // Parse and verify structure
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert!(
        json.get("error").is_some(),
        "Response should have 'error' field"
    );
    assert_eq!(json["error"], "Invalid request body");
}

/// Verify missing required JSON fields returns JSON error
#[tokio::test]
async fn test_missing_json_fields_returns_json_error() {
    let app = test_app();

    // Send empty object when product_id is required
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert!(json.get("error").is_some());
    assert!(
        json.get("details").is_some(),
        "Should include details about missing field"
    );
}

/// Verify invalid query parameters return JSON error
#[tokio::test]
async fn test_invalid_query_params_returns_json_error() {
    let app = test_app();

    // /license requires public_key query param
    // Send request with Authorization header but missing required query params
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/license")
                .header("authorization", "Bearer fake-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let content_type = response.headers().get("content-type").unwrap();
    assert!(content_type.to_str().unwrap().contains("application/json"));

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert!(json.get("error").is_some());
    assert_eq!(json["error"], "Invalid query parameters");
}

// Note: TypedHeader (for Authorization) is from axum_extra and not wrapped.
// Missing auth headers return plain text. This is acceptable since:
// 1. It's a rare edge case (malformed client request)
// 2. The handler logic returns proper JSON errors for auth failures

/// Verify application errors also return JSON
#[tokio::test]
async fn test_application_error_returns_json() {
    let app = test_app();

    // Valid request format but non-existent product
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"product_id": "nonexistent-product"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let content_type = response.headers().get("content-type").unwrap();
    assert!(content_type.to_str().unwrap().contains("application/json"));

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert!(json.get("error").is_some());
    assert_eq!(json["error"], "Not found");
}
