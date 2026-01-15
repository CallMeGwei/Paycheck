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

#[path = "../common/mod.rs"]
mod common;
use common::{
    *, ONE_YEAR, UPDATES_VALID_DAYS, ONE_DAY, ONE_HOUR_SECS,
};

use paycheck::db::AppState;
use paycheck::db::queries;
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
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

        // Create a device
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        license_id = license.id.clone();
        device_id = device.device_id.clone();

        // Create a valid JWT
        let claims = LicenseClaims {
            license_exp: Some(future_timestamp(ONE_YEAR)),
            updates_exp: Some(future_timestamp(UPDATES_VALID_DAYS)),
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
            &project.name,
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

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "refresh should succeed for valid token"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Should return a new token
    assert!(
        json["token"].is_string(),
        "response should contain token field as string"
    );
    assert!(
        !json["token"].as_str().unwrap().is_empty(),
        "returned token should not be empty"
    );
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

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "refresh should succeed to verify token structure"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    let new_token = json["token"].as_str().expect("token field should be a string");

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

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "refresh without Authorization header should return 401"
    );
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
            || response.status() == StatusCode::BAD_REQUEST,
        "refresh with invalid token should return 401 or 400, got {}",
        response.status()
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
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "non-UUID product_id should be rejected with 401"
    );
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
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        // Create JWT
        let claims = LicenseClaims {
            license_exp: Some(future_timestamp(ONE_YEAR)),
            updates_exp: Some(future_timestamp(UPDATES_VALID_DAYS)),
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
            &project.name,
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

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "refresh should fail for revoked license"
    );
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
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        // Create JWT
        let claims = LicenseClaims {
            license_exp: Some(future_timestamp(ONE_YEAR)),
            updates_exp: Some(future_timestamp(UPDATES_VALID_DAYS)),
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
            &project.name,
            &device.jti,
        )
        .unwrap();

        // Revoke this specific JTI
        queries::add_revoked_jti(&conn, &license.id, &device.jti, Some("test revocation")).unwrap();
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

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "refresh should fail when JTI is revoked"
    );
}

// ============ Expiration Edge Case Tests ============

/// Test that an expired JWT can be refreshed (this is the core feature of /refresh)
#[tokio::test]
async fn test_refresh_with_expired_jwt_succeeds() {
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
        // License valid for 365 days
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        // Create claims
        let claims = LicenseClaims {
            license_exp: Some(future_timestamp(ONE_YEAR)),
            updates_exp: Some(future_timestamp(UPDATES_VALID_DAYS)),
            tier: product.tier.clone(),
            features: product.features.clone(),
            device_id: device.device_id.clone(),
            device_type: "uuid".to_string(),
            product_id: product.id.clone(),
        };

        let private_key = master_key
            .decrypt_private_key(&project.id, &project.private_key)
            .unwrap();

        // Create a JWT that expired 1 hour ago
        token = sign_claims_with_exp_offset(
            &claims,
            &private_key,
            &license.id,
            &project.name,
            &device.jti,
            -ONE_HOUR_SECS, // 1 hour in the past
        );
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

    // Expired JWT should still refresh successfully (that's the whole point!)
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Expired JWT should be refreshable when license is still valid"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Should return a new token
    assert!(
        json["token"].is_string(),
        "response should contain token field after refreshing expired JWT"
    );
    assert!(
        !json["token"].as_str().unwrap().is_empty(),
        "new token should not be empty after refreshing expired JWT"
    );
}

/// Test that refresh fails when the license.expires_at is in the past
#[tokio::test]
async fn test_refresh_with_expired_license_fails() {
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
        // License expired 1 day ago (database-level expiration)
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(past_timestamp(ONE_DAY)));
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        // Create claims (these don't matter since DB-level expiration is checked first)
        let claims = LicenseClaims {
            license_exp: Some(future_timestamp(ONE_YEAR)), // Claims say valid, but DB says expired
            updates_exp: Some(future_timestamp(UPDATES_VALID_DAYS)),
            tier: product.tier.clone(),
            features: product.features.clone(),
            device_id: device.device_id.clone(),
            device_type: "uuid".to_string(),
            product_id: product.id.clone(),
        };

        let private_key = master_key
            .decrypt_private_key(&project.id, &project.private_key)
            .unwrap();

        // Create a valid (non-expired) JWT
        token = jwt::sign_claims(
            &claims,
            &private_key,
            &license.id,
            &project.name,
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

    // Should fail - license.expires_at is in the past
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Refresh should fail when license.expires_at is in the past"
    );
}

/// Test that refresh fails when product-derived license_exp has passed
/// (based on device.activated_at + product.license_exp_days)
#[tokio::test]
async fn test_refresh_with_expired_license_exp_fails() {
    let master_key = test_master_key();

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();

    let token: String;

    {
        let conn = pool.get().unwrap();
        paycheck::db::init_db(&conn).unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

        // Create a product with 1-day license expiration
        let input = paycheck::models::CreateProduct {
            name: "Short License".to_string(),
            tier: "pro".to_string(),
            license_exp_days: Some(1), // License expires 1 day after activation
            updates_exp_days: Some(365),
            activation_limit: 5,
            device_limit: 3,
            features: vec![],
        };
        let product = queries::create_product(&conn, &project.id, &input).unwrap();

        // License itself doesn't expire (no database-level expiration)
        let license = create_test_license(&conn, &project.id, &product.id, None);

        // Create device - but manually set activated_at to 2 days ago
        // so the license_exp (activated_at + 1 day) is in the past
        let jti = uuid::Uuid::new_v4().to_string();
        queries::create_device(
            &conn,
            &license.id,
            "test-device",
            DeviceType::Uuid,
            &jti,
            Some("Test Device"),
        )
        .unwrap();

        // Manually backdate the activation to 2 days ago
        conn.execute(
            "UPDATE devices SET activated_at = ?1 WHERE jti = ?2",
            rusqlite::params![past_timestamp(2 * ONE_DAY), &jti],
        )
        .unwrap();

        // Fetch the device to get the backdated record
        let device = queries::get_device_by_jti(&conn, &jti).unwrap().unwrap();

        // Create claims
        let claims = LicenseClaims {
            license_exp: Some(past_timestamp(ONE_DAY)), // This is what the server will calculate
            updates_exp: Some(future_timestamp(ONE_YEAR - 2 * ONE_DAY)),
            tier: product.tier.clone(),
            features: product.features.clone(),
            device_id: device.device_id.clone(),
            device_type: "uuid".to_string(),
            product_id: product.id.clone(),
        };

        let private_key = master_key
            .decrypt_private_key(&project.id, &project.private_key)
            .unwrap();

        // Create a valid JWT
        token = jwt::sign_claims(
            &claims,
            &private_key,
            &license.id,
            &project.name,
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

    // Should fail - license_exp (activated_at + license_exp_days) is in the past
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Refresh should fail when license_exp (from product settings) has passed"
    );
}
