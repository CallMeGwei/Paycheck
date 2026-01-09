//! Tests for the POST /refresh endpoint.
//!
//! The refresh endpoint allows clients to get a new JWT using their existing JWT,
//! even if the existing JWT has expired. This removes the need to store the
//! license key on the client.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde_json::Value;
use tower::ServiceExt;

mod common;
use common::*;

use paycheck::db::AppState;
use paycheck::handlers::public::refresh_token;
use paycheck::jwt::{self, LicenseClaims};
use paycheck::models::DeviceType;

/// Create an app with the refresh endpoint and test data.
/// Returns (app, token, jti, license_id, device_id)
fn setup_refresh_test() -> (Router, String, String, String, String) {
    let master_key = test_master_key();

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();

    let token: String;
    let jti: String;
    let license_id: String;
    let device_id: String;

    {
        let conn = pool.get().unwrap();
        paycheck::db::init_db(&conn).unwrap();

        // Create test hierarchy with encrypted project key
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );

        // Create a device
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        license_id = license.id.clone();
        device_id = device.device_id.clone();

        // Create a valid JWT
        let claims = LicenseClaims {
            license_exp: Some(future_timestamp(365)),
            updates_exp: Some(future_timestamp(180)),
            tier: product.tier.clone(),
            features: product.features.clone(),
            device_id: device.device_id.clone(),
            device_type: "uuid".to_string(),
            product_id: product.id.clone(),
        };

        let private_key = master_key
            .decrypt_private_key(&project.id, &project.private_key)
            .unwrap();

        token = jwt::sign_claims(
            &claims,
            &private_key,
            &license.id,
            &project.domain,
            &device.jti,
        )
        .unwrap();
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
        audit_log_enabled: true,
        master_key,
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: std::sync::Arc::new(
            paycheck::rate_limit::ActivationRateLimiter::default(),
        ),
        email_service: std::sync::Arc::new(paycheck::email::EmailService::new(None, "test@example.com".to_string())),
    };

    let app = Router::new()
        .route("/refresh", post(refresh_token))
        .with_state(state);

    (app, token, jti, license_id, device_id)
}

#[tokio::test]
async fn test_refresh_with_valid_token() {
    let (app, token, _jti, _license_id, _device_id) = setup_refresh_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/refresh")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Should return a new token
    assert!(json["token"].is_string());
    assert!(!json["token"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_refresh_returns_token_without_license_key() {
    let (app, token, _jti, _license_id, _device_id) = setup_refresh_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/refresh")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    let new_token = json["token"].as_str().unwrap();

    // Decode the new token and verify it doesn't contain license_key
    let claims = jwt::decode_unverified(new_token).unwrap();

    // The claims should not have license_key field (it was removed from the struct)
    // We verify this by checking that the serialized claims don't contain "license_key"
    let claims_json = serde_json::to_string(&claims).unwrap();
    assert!(
        !claims_json.contains("license_key"),
        "New JWT should not contain license_key"
    );
}

#[tokio::test]
async fn test_refresh_without_token_fails() {
    let (app, _token, _jti, _license_id, _device_id) = setup_refresh_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/refresh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_refresh_with_invalid_token_fails() {
    let (app, _token, _jti, _license_id, _device_id) = setup_refresh_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/refresh")
                .header("Authorization", "Bearer invalid.token.here")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail - either bad request (invalid format) or unauthorized (invalid signature)
    assert!(
        response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn test_refresh_rejects_non_uuid_product_id() {
    // This test verifies UUID validation prevents DB lookups for garbage product_ids
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
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: std::sync::Arc::new(
            paycheck::rate_limit::ActivationRateLimiter::default(),
        ),
        email_service: std::sync::Arc::new(paycheck::email::EmailService::new(None, "test@example.com".to_string())),
    };

    let app = Router::new()
        .route("/refresh", post(refresh_token))
        .with_state(state);

    // Craft a token with non-UUID product_id (base64 encoded payload)
    // Header: {"alg":"EdDSA","typ":"JWT"}
    // Payload: {"product_id":"not-a-uuid","device_id":"x","device_type":"uuid","tier":"pro","features":[],"license_exp":null,"updates_exp":null}
    let fake_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJwcm9kdWN0X2lkIjoibm90LWEtdXVpZCIsImRldmljZV9pZCI6IngiLCJkZXZpY2VfdHlwZSI6InV1aWQiLCJ0aWVyIjoicHJvIiwiZmVhdHVyZXMiOltdLCJsaWNlbnNlX2V4cCI6bnVsbCwidXBkYXRlc19leHAiOm51bGx9.fake_signature";

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/refresh")
                .header("Authorization", format!("Bearer {}", fake_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be rejected before any DB lookup
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_refresh_with_revoked_license_fails() {
    let master_key = test_master_key();

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();

    let token: String;

    {
        let conn = pool.get().unwrap();
        paycheck::db::init_db(&conn).unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        // Create JWT
        let claims = LicenseClaims {
            license_exp: Some(future_timestamp(365)),
            updates_exp: Some(future_timestamp(180)),
            tier: product.tier.clone(),
            features: product.features.clone(),
            device_id: device.device_id.clone(),
            device_type: "uuid".to_string(),
            product_id: product.id.clone(),
        };

        let private_key = master_key
            .decrypt_private_key(&project.id, &project.private_key)
            .unwrap();
        token = jwt::sign_claims(
            &claims,
            &private_key,
            &license.id,
            &project.domain,
            &device.jti,
        )
        .unwrap();

        // Revoke the license
        queries::revoke_license(&conn, &license.id).unwrap();
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
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: std::sync::Arc::new(
            paycheck::rate_limit::ActivationRateLimiter::default(),
        ),
        email_service: std::sync::Arc::new(paycheck::email::EmailService::new(None, "test@example.com".to_string())),
    };

    let app = Router::new()
        .route("/refresh", post(refresh_token))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/refresh")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_refresh_with_revoked_jti_fails() {
    let master_key = test_master_key();

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();

    let token: String;

    {
        let conn = pool.get().unwrap();
        paycheck::db::init_db(&conn).unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        // Create JWT
        let claims = LicenseClaims {
            license_exp: Some(future_timestamp(365)),
            updates_exp: Some(future_timestamp(180)),
            tier: product.tier.clone(),
            features: product.features.clone(),
            device_id: device.device_id.clone(),
            device_type: "uuid".to_string(),
            product_id: product.id.clone(),
        };

        let private_key = master_key
            .decrypt_private_key(&project.id, &project.private_key)
            .unwrap();
        token = jwt::sign_claims(
            &claims,
            &private_key,
            &license.id,
            &project.domain,
            &device.jti,
        )
        .unwrap();

        // Revoke this specific JTI
        queries::add_revoked_jti(&conn, &license.id, &device.jti).unwrap();
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
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: std::sync::Arc::new(
            paycheck::rate_limit::ActivationRateLimiter::default(),
        ),
        email_service: std::sync::Arc::new(paycheck::email::EmailService::new(None, "test@example.com".to_string())),
    };

    let app = Router::new()
        .route("/refresh", post(refresh_token))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/refresh")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
