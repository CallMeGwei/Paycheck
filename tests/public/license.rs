//! Tests for the GET /license endpoint.
//!
//! The license endpoint allows clients to get license information using their
//! JWT token (passed in the Authorization header).

use axum::{body::Body, http::Request};
use serde_json::Value;
use tower::ServiceExt;

#[path = "../common/mod.rs"]
mod common;
use common::{
    create_test_app_state, create_test_device, create_test_license, create_test_org,
    create_test_product, create_test_project, future_timestamp, past_timestamp, public_app,
    queries, test_master_key, CreateProduct, Device, DeviceType, Product, Project, ONE_DAY,
    ONE_YEAR, UPDATES_VALID_DAYS,
};

use paycheck::jwt::{self, LicenseClaims};

/// Helper to create a valid JWT for testing
fn create_test_jwt(
    project: &Project,
    product: &Product,
    license_id: &str,
    device: &Device,
) -> String {
    let master_key = test_master_key();

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

    jwt::sign_claims(
        &claims,
        &private_key,
        license_id,
        &project.name,
        &device.jti,
    )
    .unwrap()
}

/// Helper to setup test data and return (app, state, token, public_key)
fn setup_license_test() -> (axum::Router, paycheck::db::AppState, String, String) {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_jwt(&project, &product, &license.id, &device);
        public_key = project.public_key.clone();
    }

    let app = public_app(state.clone());
    (app, state, token, public_key)
}

#[tokio::test]
async fn test_license_with_valid_jwt_returns_info() {
    let (app, _state, token, public_key) = setup_license_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/license?public_key={}",
                    urlencoding::encode(&public_key)
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "license info request should succeed with valid JWT"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["status"], "active",
        "license status should be active for valid license"
    );
    assert!(
        json["created_at"].is_i64(),
        "created_at should be a timestamp"
    );
    assert!(
        json["expires_at"].is_i64(),
        "expires_at should be a timestamp"
    );
    assert!(
        json["activation_count"].is_i64(),
        "activation_count should be an integer"
    );
    assert!(
        json["activation_limit"].is_i64(),
        "activation_limit should be an integer"
    );
    assert!(
        json["device_count"].is_i64(),
        "device_count should be an integer"
    );
    assert!(
        json["device_limit"].is_i64(),
        "device_limit should be an integer"
    );
    assert!(
        json["devices"].is_array(),
        "devices should be an array of device objects"
    );
}

#[tokio::test]
async fn test_license_with_devices_returns_device_list() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

        // Add some devices
        let device1 = create_test_device(&conn, &license.id, "device-1", DeviceType::Uuid);
        let _device2 = create_test_device(&conn, &license.id, "device-2", DeviceType::Machine);

        token = create_test_jwt(&project, &product, &license.id, &device1);
        public_key = project.public_key.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/license?public_key={}",
                    urlencoding::encode(&public_key)
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "license info request should succeed with valid JWT"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["device_count"], 2,
        "device_count should reflect actual number of registered devices"
    );
    let devices = json["devices"].as_array().unwrap();
    assert_eq!(
        devices.len(),
        2,
        "devices array should contain all registered devices"
    );

    // Check device info structure
    let device = &devices[0];
    assert!(
        device["device_id"].is_string(),
        "device should have device_id string"
    );
    assert!(
        device["device_type"].is_string(),
        "device should have device_type string"
    );
    assert!(
        device["activated_at"].is_i64(),
        "device should have activated_at timestamp"
    );
    assert!(
        device["last_seen_at"].is_i64(),
        "device should have last_seen_at timestamp"
    );
}

#[tokio::test]
async fn test_license_missing_auth_header_returns_error() {
    let (app, _state, _token, public_key) = setup_license_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/license?public_key={}",
                    urlencoding::encode(&public_key)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return 400 (bad request) for missing header
    assert!(
        response.status() == axum::http::StatusCode::BAD_REQUEST
            || response.status() == axum::http::StatusCode::UNAUTHORIZED,
        "missing Authorization header should return 400 or 401"
    );
}

#[tokio::test]
async fn test_license_invalid_jwt_returns_error() {
    let (app, _state, _token, public_key) = setup_license_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/license?public_key={}",
                    urlencoding::encode(&public_key)
                ))
                .header("Authorization", "Bearer invalid-jwt-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail with bad request or unauthorized
    assert!(
        response.status() == axum::http::StatusCode::BAD_REQUEST
            || response.status() == axum::http::StatusCode::UNAUTHORIZED,
        "invalid JWT should return 400 or 401"
    );
}

#[tokio::test]
async fn test_license_revoked_shows_revoked_status() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_jwt(&project, &product, &license.id, &device);
        public_key = project.public_key.clone();

        // Revoke the license
        queries::revoke_license(&conn, &license.id).unwrap();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/license?public_key={}",
                    urlencoding::encode(&public_key)
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "license info request should succeed even for revoked license"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["status"], "revoked",
        "revoked license should show revoked status"
    );
}

#[tokio::test]
async fn test_license_expired_shows_expired_status() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(past_timestamp(ONE_DAY)), // Expired 1 day ago
        );
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_jwt(&project, &product, &license.id, &device);
        public_key = project.public_key.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/license?public_key={}",
                    urlencoding::encode(&public_key)
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "license info request should succeed even for expired license"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["status"], "expired",
        "expired license should show expired status"
    );
}

#[tokio::test]
async fn test_license_perpetual_shows_active_status() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            None, // Perpetual license
        );
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_jwt(&project, &product, &license.id, &device);
        public_key = project.public_key.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/license?public_key={}",
                    urlencoding::encode(&public_key)
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "license info request should succeed for perpetual license"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["status"], "active",
        "perpetual license should show active status"
    );
    assert!(
        json.get("expires_at").is_none() || json["expires_at"].is_null(),
        "perpetual license should not have expires_at"
    );
}

#[tokio::test]
async fn test_license_missing_public_key_returns_error() {
    let (app, _state, token, _public_key) = setup_license_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/license")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "missing public_key query param should return 400"
    );
}

#[tokio::test]
async fn test_license_shows_correct_limits() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

        // Create product with specific limits
        let input = CreateProduct {
            name: "Limited Plan".to_string(),
            tier: "limited".to_string(),
            license_exp_days: Some(ONE_YEAR as i32),
            updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
            activation_limit: 10,
            device_limit: 5,
            features: vec![],
        };
        let product =
            queries::create_product(&conn, &project.id, &input).expect("Failed to create product");

        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_jwt(&project, &product, &license.id, &device);
        public_key = project.public_key.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/license?public_key={}",
                    urlencoding::encode(&public_key)
                ))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "license info request should succeed"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["activation_limit"], 10,
        "activation_limit should match product configuration"
    );
    assert_eq!(
        json["device_limit"], 5,
        "device_limit should match product configuration"
    );
}
