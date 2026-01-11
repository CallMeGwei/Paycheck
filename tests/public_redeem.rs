//! Tests for the POST /redeem endpoint:
//! Redeem an activation code for a JWT token and register a device.

use axum::{body::Body, http::Request};
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::*;

// ============================================================================
// POST /redeem - Redeem with activation code
// ============================================================================

#[tokio::test]
async fn test_redeem_with_valid_code_returns_token() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let code: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );

        // Create an activation code
        let activation_code =
            queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                .unwrap();

        public_key = project.public_key.clone();
        code = activation_code.code.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&json!({
                    "public_key": public_key,
                    "code": code,
                    "device_id": "test-device",
                    "device_type": "uuid"
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert!(json["token"].is_string());
    assert!(!json["token"].as_str().unwrap().is_empty());
    assert!(json["tier"].is_string());
    assert!(json["features"].is_array());
    // Should return a new activation code for future use
    assert!(json["activation_code"].is_string());
    assert!(json["activation_code_expires_at"].is_i64());
}

#[tokio::test]
async fn test_redeem_with_invalid_device_type_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let code: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );

        let activation_code =
            queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                .unwrap();

        public_key = project.public_key.clone();
        code = activation_code.code.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&json!({
                    "public_key": public_key,
                    "code": code,
                    "device_id": "test-device",
                    "device_type": "invalid"
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_redeem_code_not_found_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

        public_key = project.public_key.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&json!({
                    "public_key": public_key,
                    "code": "invalid-code",
                    "device_id": "test-device",
                    "device_type": "uuid"
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_redeem_code_already_used_returns_forbidden() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let code: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );

        let activation_code =
            queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                .unwrap();

        // Mark the code as used
        queries::mark_activation_code_used(&conn, &activation_code.id).unwrap();

        public_key = project.public_key.clone();
        code = activation_code.code.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&json!({
                    "public_key": public_key,
                    "code": code,
                    "device_id": "test-device",
                    "device_type": "uuid"
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_redeem_code_creates_device_record() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let code: String;
    let license_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );

        let activation_code =
            queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                .unwrap();

        public_key = project.public_key.clone();
        code = activation_code.code.clone();
        license_id = license.id.clone();
    }

    let app = public_app(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&json!({
                    "public_key": public_key,
                    "code": code,
                    "device_id": "new-device-123",
                    "device_type": "uuid",
                    "device_name": "My Device"
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Verify device was created
    let conn = state.db.get().unwrap();
    let devices = queries::list_devices_for_license(&conn, &license_id).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, "new-device-123");
    assert_eq!(devices[0].name, Some("My Device".to_string()));
}

#[tokio::test]
async fn test_redeem_revoked_license_returns_forbidden() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let code: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );

        let activation_code =
            queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                .unwrap();

        // Revoke the license
        queries::revoke_license(&conn, &license.id).unwrap();

        public_key = project.public_key.clone();
        code = activation_code.code.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&json!({
                    "public_key": public_key,
                    "code": code,
                    "device_id": "test-device",
                    "device_type": "uuid"
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_redeem_expired_license_returns_forbidden() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let code: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(past_timestamp(1)), // Expired
        );

        let activation_code =
            queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                .unwrap();

        public_key = project.public_key.clone();
        code = activation_code.code.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&json!({
                    "public_key": public_key,
                    "code": code,
                    "device_id": "test-device",
                    "device_type": "uuid"
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_redeem_device_limit_exceeded_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let code: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

        // Create product with device_limit = 1
        let input = CreateProduct {
            name: "Limited Plan".to_string(),
            tier: "limited".to_string(),
            license_exp_days: Some(365),
            updates_exp_days: Some(180),
            activation_limit: 10,
            device_limit: 1, // Only 1 device allowed
            features: vec![],
        };
        let product =
            queries::create_product(&conn, &project.id, &input).expect("Failed to create product");

        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );

        // Create a device (using up the limit)
        create_test_device(&conn, &license.id, "device-1", DeviceType::Uuid);

        let activation_code =
            queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                .unwrap();

        public_key = project.public_key.clone();
        code = activation_code.code.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&json!({
                    "public_key": public_key,
                    "code": code,
                    "device_id": "device-2",
                    "device_type": "uuid"
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail because device limit exceeded
    assert!(
        response.status() == axum::http::StatusCode::FORBIDDEN
            || response.status() == axum::http::StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn test_redeem_same_device_returns_token() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let code: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );

        // Create an existing device
        create_test_device(&conn, &license.id, "existing-device", DeviceType::Uuid);

        let activation_code =
            queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                .unwrap();

        public_key = project.public_key.clone();
        code = activation_code.code.clone();
    }

    let app = public_app(state);

    // Redeem with the same device ID (should work, reactivating the device)
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&json!({
                    "public_key": public_key,
                    "code": code,
                    "device_id": "existing-device",
                    "device_type": "uuid"
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn test_redeem_with_public_key() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let code: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );

        let activation_code =
            queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                .unwrap();

        public_key = project.public_key.clone();
        code = activation_code.code.clone();
    }

    let app = public_app(state);

    // Use public_key instead of project_id
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&json!({
                    "public_key": public_key,
                    "code": code,
                    "device_id": "test-device",
                    "device_type": "uuid"
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}
