//! Tests for the GET /license endpoint.
//!
//! The license endpoint allows clients to get license information using their
//! license key (passed in the Authorization header).

use axum::{body::Body, http::Request};
use serde_json::Value;
use tower::ServiceExt;

mod common;
use common::*;

/// Helper to setup test data and return (app, state, license_key, project_id)
fn setup_license_test() -> (axum::Router, paycheck::db::AppState, String, String) {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_key: String;
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

        license_key = license.key.clone();
        project_id = project.id.clone();
    }

    let app = public_app(state.clone());
    (app, state, license_key, project_id)
}

#[tokio::test]
async fn test_license_with_valid_key_returns_info() {
    let (app, _state, license_key, project_id) = setup_license_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/license?project_id={}", project_id))
                .header("Authorization", format!("Bearer {}", license_key))
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

    assert_eq!(json["status"], "active");
    assert!(json["created_at"].is_i64());
    assert!(json["expires_at"].is_i64());
    assert!(json["activation_count"].is_i64());
    assert!(json["activation_limit"].is_i64());
    assert!(json["device_count"].is_i64());
    assert!(json["device_limit"].is_i64());
    assert!(json["devices"].is_array());
}

#[tokio::test]
async fn test_license_with_devices_returns_device_list() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_key: String;
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

        // Add some devices
        create_test_device(&conn, &license.id, "device-1", DeviceType::Uuid);
        create_test_device(&conn, &license.id, "device-2", DeviceType::Machine);

        license_key = license.key.clone();
        project_id = project.id.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/license?project_id={}", project_id))
                .header("Authorization", format!("Bearer {}", license_key))
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

    assert_eq!(json["device_count"], 2);
    let devices = json["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 2);

    // Check device info structure
    let device = &devices[0];
    assert!(device["device_id"].is_string());
    assert!(device["device_type"].is_string());
    assert!(device["activated_at"].is_i64());
    assert!(device["last_seen_at"].is_i64());
}

#[tokio::test]
async fn test_license_missing_auth_header_returns_error() {
    let (app, _state, _license_key, project_id) = setup_license_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/license?project_id={}", project_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return 400 (bad request) for missing header
    assert!(
        response.status() == axum::http::StatusCode::BAD_REQUEST
            || response.status() == axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn test_license_invalid_key_returns_not_found() {
    let (app, _state, _license_key, project_id) = setup_license_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/license?project_id={}", project_id))
                .header("Authorization", "Bearer invalid-license-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_license_wrong_project_returns_not_found() {
    let (app, _state, license_key, _project_id) = setup_license_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/license?project_id=wrong-project-id")
                .header("Authorization", format!("Bearer {}", license_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return 404 to avoid revealing the license exists in another project
    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_license_revoked_shows_revoked_status() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_key: String;
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

        license_key = license.key.clone();
        project_id = project.id.clone();

        // Revoke the license
        queries::revoke_license_key(&conn, &license.id).unwrap();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/license?project_id={}", project_id))
                .header("Authorization", format!("Bearer {}", license_key))
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

    assert_eq!(json["status"], "revoked");
}

#[tokio::test]
async fn test_license_expired_shows_expired_status() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_key: String;
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
            Some(past_timestamp(1)), // Expired 1 day ago
            &master_key,
        );

        license_key = license.key.clone();
        project_id = project.id.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/license?project_id={}", project_id))
                .header("Authorization", format!("Bearer {}", license_key))
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

    assert_eq!(json["status"], "expired");
}

#[tokio::test]
async fn test_license_perpetual_shows_active_status() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_key: String;
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
            None, // Perpetual license
            &master_key,
        );

        license_key = license.key.clone();
        project_id = project.id.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/license?project_id={}", project_id))
                .header("Authorization", format!("Bearer {}", license_key))
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

    assert_eq!(json["status"], "active");
    assert!(
        json.get("expires_at").is_none() || json["expires_at"].is_null(),
        "Perpetual license should not have expires_at"
    );
}

#[tokio::test]
async fn test_license_missing_project_id_returns_error() {
    let (app, _state, license_key, _project_id) = setup_license_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/license")
                .header("Authorization", format!("Bearer {}", license_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_license_shows_correct_limits() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_key: String;
    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

        // Create product with specific limits
        let input = CreateProduct {
            name: "Limited Plan".to_string(),
            tier: "limited".to_string(),
            license_exp_days: Some(365),
            updates_exp_days: Some(180),
            activation_limit: 10,
            device_limit: 5,
            features: vec![],
        };
        let product =
            queries::create_product(&conn, &project.id, &input).expect("Failed to create product");

        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            &project.license_key_prefix,
            Some(future_timestamp(365)),
            &master_key,
        );

        license_key = license.key.clone();
        project_id = project.id.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/license?project_id={}", project_id))
                .header("Authorization", format!("Bearer {}", license_key))
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

    assert_eq!(json["activation_limit"], 10);
    assert_eq!(json["device_limit"], 5);
}
