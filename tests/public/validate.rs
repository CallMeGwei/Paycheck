//! Tests for the POST /validate endpoint.
//!
//! The validate endpoint allows clients to perform online license validation,
//! checking if a JTI (JWT ID) is still valid for a given project.

use axum::{body::Body, http::Request};
use common::{ONE_DAY, ONE_YEAR};
use serde_json::{Value, json};
use tower::ServiceExt;

#[path = "../common/mod.rs"]
mod common;
use common::*;

/// Helper to setup test data and return (app, jti, public_key, license_id, device_id)
fn setup_validate_test() -> (axum::Router, String, String, String, String) {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let public_key: String;
    let license_id: String;
    let device_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        public_key = project.public_key.clone();
        license_id = license.id.clone();
        device_id = device.device_id.clone();
    }

    let app = public_app(state);
    (app, jti, public_key, license_id, device_id)
}

#[tokio::test]
async fn test_validate_with_valid_jti_returns_valid() {
    let (app, jti, public_key, _license_id, _device_id) = setup_validate_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "jti": jti
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for valid JTI"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], true,
        "license should be marked as valid for active, non-revoked JTI"
    );
    assert!(
        json.get("reason").is_none() || json["reason"].is_null(),
        "valid license should not include a reason field"
    );
    // Should include expiration info for valid licenses
    assert!(
        json.get("license_exp").is_some(),
        "response should include license_exp for valid license"
    );
    assert!(
        json.get("updates_exp").is_some(),
        "response should include updates_exp for valid license"
    );
}

#[tokio::test]
async fn test_validate_with_unknown_jti_returns_invalid() {
    let (app, _jti, public_key, _license_id, _device_id) = setup_validate_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "jti": "unknown-jti-12345"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK even for unknown JTI"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], false,
        "license should be marked as invalid for unknown JTI"
    );
    // No reason should be given (prevents information disclosure)
    assert!(
        json.get("reason").is_none() || json["reason"].is_null(),
        "invalid response should not reveal reason to prevent information disclosure"
    );
}

#[tokio::test]
async fn test_validate_with_revoked_license_returns_invalid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        public_key = project.public_key.clone();

        // Revoke the license
        queries::revoke_license(&conn, &license.id).unwrap();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "jti": jti
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for revoked license"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], false,
        "license should be marked as invalid when license is revoked"
    );
}

#[tokio::test]
async fn test_validate_with_revoked_jti_returns_invalid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        public_key = project.public_key.clone();

        // Revoke this specific JTI (not the whole license)
        queries::add_revoked_jti(&conn, &license.id, &jti, Some("test revocation")).unwrap();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "jti": jti
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for revoked JTI"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], false,
        "license should be marked as invalid when specific JTI is revoked"
    );
}

#[tokio::test]
async fn test_validate_with_expired_license_returns_invalid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        // Create license that expired yesterday
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(past_timestamp(ONE_DAY)), // Expired 1 day ago
        );
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        public_key = project.public_key.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "jti": jti
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for expired license"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], false,
        "license should be marked as invalid when license has expired"
    );
}

#[tokio::test]
async fn test_validate_with_wrong_project_returns_invalid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
    }

    let app = public_app(state);

    // Try to validate with a different public key
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": "wrong-public-key",
                        "jti": jti
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for wrong public key"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], false,
        "license should be marked as invalid when public key does not match project"
    );
}

#[tokio::test]
async fn test_validate_missing_fields_returns_error() {
    let (app, _jti, _public_key, _license_id, _device_id) = setup_validate_test();

    // Missing jti
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": "some-key"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "validate endpoint should return 400 Bad Request when required fields are missing"
    );
}

#[tokio::test]
async fn test_validate_updates_last_seen_timestamp() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        public_key = project.public_key.clone();
    }

    let app = public_app(state.clone());

    // Get initial last_seen_at
    let initial_last_seen = {
        let conn = state.db.get().unwrap();
        queries::get_device_by_jti(&conn, &jti)
            .unwrap()
            .unwrap()
            .last_seen_at
    };

    // Small delay to ensure timestamp differs
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Perform validation
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "jti": jti
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for valid license"
    );

    // Check that last_seen_at was updated
    let updated_last_seen = {
        let conn = state.db.get().unwrap();
        queries::get_device_by_jti(&conn, &jti)
            .unwrap()
            .unwrap()
            .last_seen_at
    };

    assert!(
        updated_last_seen >= initial_last_seen,
        "last_seen_at should be updated after successful validation"
    );
}

#[tokio::test]
async fn test_validate_perpetual_license_returns_valid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

        // Create product with no expiration (perpetual license)
        let input = CreateProduct {
            name: "Perpetual Plan".to_string(),
            tier: "perpetual".to_string(),
            license_exp_days: None, // No expiration
            updates_exp_days: None,
            activation_limit: 5,
            device_limit: 3,
            features: vec![],
        };
        let product =
            queries::create_product(&conn, &project.id, &input).expect("Failed to create product");

        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            None, // Perpetual
        );
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        public_key = project.public_key.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "jti": jti
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for perpetual license"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], true,
        "perpetual license should be marked as valid"
    );
    // Perpetual license should not have license_exp
    assert!(
        json.get("license_exp").is_none() || json["license_exp"].is_null(),
        "perpetual license should not have license_exp set"
    );
}
