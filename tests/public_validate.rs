//! Tests for the GET /validate endpoint.
//!
//! The validate endpoint allows clients to perform online license validation,
//! checking if a JTI (JWT ID) is still valid for a given project.

use axum::{body::Body, http::Request};
use serde_json::Value;
use tower::ServiceExt;

mod common;
use common::*;

/// Helper to setup test data and return (app, jti, project_id, license_id, device_id)
fn setup_validate_test() -> (axum::Router, String, String, String, String) {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let project_id: String;
    let license_id: String;
    let device_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            &project.license_key_prefix,
            Some(future_timestamp(365)),
            &master_key,
        );
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        project_id = project.id.clone();
        license_id = license.id.clone();
        device_id = device.device_id.clone();
    }

    let app = public_app(state);
    (app, jti, project_id, license_id, device_id)
}

#[tokio::test]
async fn test_validate_with_valid_jti_returns_valid() {
    let (app, jti, project_id, _license_id, _device_id) = setup_validate_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/validate?project_id={}&jti={}", project_id, jti))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(json["valid"], true);
    assert!(json.get("reason").is_none() || json["reason"].is_null());
    // Should include expiration info for valid licenses
    assert!(json.get("license_exp").is_some());
    assert!(json.get("updates_exp").is_some());
}

#[tokio::test]
async fn test_validate_with_unknown_jti_returns_invalid() {
    let (app, _jti, project_id, _license_id, _device_id) = setup_validate_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/validate?project_id={}&jti=unknown-jti-12345",
                    project_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(json["valid"], false);
    // No reason should be given (prevents information disclosure)
    assert!(json.get("reason").is_none() || json["reason"].is_null());
}

#[tokio::test]
async fn test_validate_with_revoked_license_returns_invalid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            &project.license_key_prefix,
            Some(future_timestamp(365)),
            &master_key,
        );
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        project_id = project.id.clone();

        // Revoke the license
        queries::revoke_license_key(&conn, &license.id).unwrap();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/validate?project_id={}&jti={}", project_id, jti))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(json["valid"], false);
}

#[tokio::test]
async fn test_validate_with_revoked_jti_returns_invalid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            &project.license_key_prefix,
            Some(future_timestamp(365)),
            &master_key,
        );
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        project_id = project.id.clone();

        // Revoke this specific JTI (not the whole license)
        queries::add_revoked_jti(&conn, &license.id, &jti, &master_key).unwrap();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/validate?project_id={}&jti={}", project_id, jti))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(json["valid"], false);
}

#[tokio::test]
async fn test_validate_with_expired_license_returns_invalid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let project_id: String;

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
            &project.license_key_prefix,
            Some(past_timestamp(1)), // Expired 1 day ago
            &master_key,
        );
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        project_id = project.id.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/validate?project_id={}&jti={}", project_id, jti))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(json["valid"], false);
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
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            &project.license_key_prefix,
            Some(future_timestamp(365)),
            &master_key,
        );
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
    }

    let app = public_app(state);

    // Try to validate with a different project ID
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/validate?project_id=wrong-project-id&jti={}", jti))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(json["valid"], false);
}

#[tokio::test]
async fn test_validate_missing_query_params_returns_error() {
    let (app, _jti, _project_id, _license_id, _device_id) = setup_validate_test();

    // Missing jti
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/validate?project_id=some-project")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_validate_updates_last_seen_timestamp() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            &project.license_key_prefix,
            Some(future_timestamp(365)),
            &master_key,
        );
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        project_id = project.id.clone();
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
                .method("GET")
                .uri(format!("/validate?project_id={}&jti={}", project_id, jti))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

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
        "last_seen_at should be updated after validation"
    );
}

#[tokio::test]
async fn test_validate_perpetual_license_returns_valid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let project_id: String;

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
            stripe_price_id: None,
            price_cents: Some(4999),
            currency: Some("usd".to_string()),
            ls_variant_id: None,
        };
        let product =
            queries::create_product(&conn, &project.id, &input).expect("Failed to create product");

        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            &project.license_key_prefix,
            None, // Perpetual
            &master_key,
        );
        let device = create_test_device(&conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        project_id = project.id.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/validate?project_id={}&jti={}", project_id, jti))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(json["valid"], true);
    // Perpetual license should not have license_exp
    assert!(
        json.get("license_exp").is_none() || json["license_exp"].is_null(),
        "Perpetual license should not have license_exp"
    );
}
