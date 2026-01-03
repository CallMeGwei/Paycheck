//! Tests for the redeem endpoints:
//! - GET /redeem - Redeem using short-lived code
//! - POST /redeem/key - Redeem using permanent license key
//! - POST /redeem/code - Generate new redemption code

use axum::{body::Body, http::Request};
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::*;

// ============================================================================
// GET /redeem - Redeem with short-lived code
// ============================================================================

#[tokio::test]
async fn test_redeem_code_with_valid_code_returns_token() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
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
            &project.license_key_prefix,
            Some(future_timestamp(365)),
            &master_key,
        );

        // Create a redemption code
        let redemption_code = queries::create_redemption_code(&conn, &license.id).unwrap();

        project_id = project.id.clone();
        code = redemption_code.code.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/redeem?project_id={}&code={}&device_id=test-device&device_type=uuid",
                    project_id, code
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

    assert!(json["token"].is_string());
    assert!(!json["token"].as_str().unwrap().is_empty());
    assert!(json["tier"].is_string());
    assert!(json["features"].is_array());
    assert!(json["redemption_code"].is_string());
    assert!(json["redemption_code_expires_at"].is_i64());
}

#[tokio::test]
async fn test_redeem_code_with_invalid_device_type_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
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
            &project.license_key_prefix,
            Some(future_timestamp(365)),
            &master_key,
        );

        let redemption_code = queries::create_redemption_code(&conn, &license.id).unwrap();

        project_id = project.id.clone();
        code = redemption_code.code.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/redeem?project_id={}&code={}&device_id=test-device&device_type=invalid",
                    project_id, code
                ))
                .body(Body::empty())
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

    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

        project_id = project.id.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/redeem?project_id={}&code=invalid-code&device_id=test-device&device_type=uuid",
                    project_id
                ))
                .body(Body::empty())
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

    let project_id: String;
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
            &project.license_key_prefix,
            Some(future_timestamp(365)),
            &master_key,
        );

        let redemption_code = queries::create_redemption_code(&conn, &license.id).unwrap();

        // Mark the code as used
        queries::mark_redemption_code_used(&conn, &redemption_code.id).unwrap();

        project_id = project.id.clone();
        code = redemption_code.code.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/redeem?project_id={}&code={}&device_id=test-device&device_type=uuid",
                    project_id, code
                ))
                .body(Body::empty())
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

    let project_id: String;
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
            &project.license_key_prefix,
            Some(future_timestamp(365)),
            &master_key,
        );

        let redemption_code = queries::create_redemption_code(&conn, &license.id).unwrap();

        project_id = project.id.clone();
        code = redemption_code.code.clone();
        license_id = license.id.clone();
    }

    let app = public_app(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/redeem?project_id={}&code={}&device_id=new-device-123&device_type=uuid&device_name=My%20Device",
                    project_id, code
                ))
                .body(Body::empty())
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

// ============================================================================
// POST /redeem/key - Redeem with license key
// ============================================================================

#[tokio::test]
async fn test_redeem_key_with_valid_key_in_body_returns_token() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let license_key: String;

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

        project_id = project.id.clone();
        license_key = license.key.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "key": license_key,
        "device_id": "test-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/key")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
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
}

#[tokio::test]
async fn test_redeem_key_with_valid_key_in_header_returns_token() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let license_key: String;

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

        project_id = project.id.clone();
        license_key = license.key.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "device_id": "test-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/key")
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", license_key))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn test_redeem_key_missing_key_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

        project_id = project.id.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "device_id": "test-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/key")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_redeem_key_not_found_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

        project_id = project.id.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "key": "invalid-license-key",
        "device_id": "test-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/key")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_redeem_key_revoked_license_returns_forbidden() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let license_key: String;

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

        project_id = project.id.clone();
        license_key = license.key.clone();

        // Revoke the license
        queries::revoke_license_key(&conn, &license.id).unwrap();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "key": license_key,
        "device_id": "test-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/key")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_redeem_key_expired_license_returns_forbidden() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let license_key: String;

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
            Some(past_timestamp(1)), // Expired
            &master_key,
        );

        project_id = project.id.clone();
        license_key = license.key.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "key": license_key,
        "device_id": "test-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/key")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_redeem_key_wrong_project_returns_not_found() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_key: String;

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
    }

    let app = public_app(state);

    let body = json!({
        "project_id": "wrong-project-id",
        "key": license_key,
        "device_id": "test-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/key")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_redeem_key_invalid_device_type_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let license_key: String;

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

        project_id = project.id.clone();
        license_key = license.key.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "key": license_key,
        "device_id": "test-device",
        "device_type": "invalid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/key")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_redeem_key_device_limit_exceeded_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let license_key: String;

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
            &project.license_key_prefix,
            Some(future_timestamp(365)),
            &master_key,
        );

        // Create a device (using up the limit)
        create_test_device(&conn, &license.id, "device-1", DeviceType::Uuid);

        project_id = project.id.clone();
        license_key = license.key.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "key": license_key,
        "device_id": "device-2", // Trying to add second device
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/key")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
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
async fn test_redeem_key_same_device_returns_token() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let license_key: String;

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

        // Create an existing device
        create_test_device(&conn, &license.id, "existing-device", DeviceType::Uuid);

        project_id = project.id.clone();
        license_key = license.key.clone();
    }

    let app = public_app(state);

    // Redeem with the same device ID (should work, reactivating the device)
    let body = json!({
        "project_id": project_id,
        "key": license_key,
        "device_id": "existing-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/key")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

// ============================================================================
// POST /redeem/code - Generate redemption code
// ============================================================================

#[tokio::test]
async fn test_generate_code_with_valid_key_returns_code() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_key: String;

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
    }

    let app = public_app(state);

    let body = json!({
        "key": license_key
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/code")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert!(json["code"].is_string());
    assert!(!json["code"].as_str().unwrap().is_empty());
    assert!(json["expires_at"].is_i64());
}

#[tokio::test]
async fn test_generate_code_with_key_in_header() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_key: String;

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
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/code")
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", license_key))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn test_generate_code_missing_key_returns_error() {
    let state = create_test_app_state();

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let _project = create_test_project(&conn, &org.id, "Test Project", &test_master_key());
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/code")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_generate_code_invalid_key_returns_not_found() {
    let state = create_test_app_state();
    let app = public_app(state);

    let body = json!({
        "key": "invalid-license-key"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/code")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_generate_code_revoked_license_returns_forbidden() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_key: String;

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

        queries::revoke_license_key(&conn, &license.id).unwrap();
    }

    let app = public_app(state);

    let body = json!({
        "key": license_key
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/code")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_generate_code_expired_license_returns_forbidden() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_key: String;

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
            Some(past_timestamp(1)), // Expired
            &master_key,
        );

        license_key = license.key.clone();
    }

    let app = public_app(state);

    let body = json!({
        "key": license_key
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem/code")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
}
