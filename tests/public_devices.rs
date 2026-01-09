//! Tests for the POST /devices/deactivate endpoint.
//!
//! The deactivate endpoint allows a device to self-deactivate using its JWT.

use axum::{body::Body, http::Request};
use serde_json::Value;
use tower::ServiceExt;

mod common;
use common::*;

use paycheck::jwt::{self, LicenseClaims};

/// Helper to create a valid JWT for testing
fn create_test_jwt(
    _state: &paycheck::db::AppState,
    project: &Project,
    product: &Product,
    license_id: &str,
    device: &Device,
) -> String {
    let master_key = test_master_key();

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

    jwt::sign_claims(
        &claims,
        &private_key,
        license_id,
        &project.domain,
        &device.jti,
    )
    .unwrap()
}

#[tokio::test]
async fn test_deactivate_with_valid_jwt_removes_device() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
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
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        license_id = license.id.clone();
        token = create_test_jwt(&state, &project, &product, &license.id, &device);
    }

    let app = public_app(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/deactivate")
                .header("Authorization", format!("Bearer {}", token))
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

    assert_eq!(json["deactivated"], true);
    assert_eq!(json["remaining_devices"], 0);

    // Verify device was actually removed
    let conn = state.db.get().unwrap();
    let devices = queries::list_devices_for_license(&conn, &license_id).unwrap();
    assert_eq!(devices.len(), 0);
}

#[tokio::test]
async fn test_deactivate_adds_jti_to_revoked_list() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let license_id: String;
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
            Some(future_timestamp(365)),
        );
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        license_id = license.id.clone();
        jti = device.jti.clone();
        token = create_test_jwt(&state, &project, &product, &license.id, &device);
    }

    let app = public_app(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/deactivate")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Verify JTI was added to revoked list
    let conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&conn, &license_id)
        .unwrap()
        .unwrap();
    assert!(
        license.revoked_jtis.contains(&jti),
        "JTI should be in revoked list"
    );
}

#[tokio::test]
async fn test_deactivate_returns_remaining_device_count() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;

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

        // Create multiple devices
        let device1 = create_test_device(&conn, &license.id, "device-1", DeviceType::Uuid);
        let _device2 = create_test_device(&conn, &license.id, "device-2", DeviceType::Uuid);
        let _device3 = create_test_device(&conn, &license.id, "device-3", DeviceType::Uuid);

        // We'll deactivate device1
        token = create_test_jwt(&state, &project, &product, &license.id, &device1);
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/deactivate")
                .header("Authorization", format!("Bearer {}", token))
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

    assert_eq!(json["deactivated"], true);
    assert_eq!(json["remaining_devices"], 2); // 3 - 1 = 2
}

#[tokio::test]
async fn test_deactivate_missing_auth_returns_error() {
    let state = create_test_app_state();
    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/deactivate")
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
async fn test_deactivate_malformed_jwt_returns_error() {
    let state = create_test_app_state();
    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/deactivate")
                .header("Authorization", "Bearer not-a-jwt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail with bad request or unauthorized
    assert!(
        response.status() == axum::http::StatusCode::BAD_REQUEST
            || response.status() == axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn test_deactivate_invalid_signature_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

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
        let _device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);
    }

    let app = public_app(state);

    // Create a JWT with a valid format but signed with wrong key
    // This is a valid JWT structure but wrong signature
    let fake_jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJwcm9kdWN0X2lkIjoiMTIzNDU2Nzg5LWFiY2QtZWZnaCIsImRldmljZV9pZCI6InRlc3QiLCJkZXZpY2VfdHlwZSI6InV1aWQiLCJ0aWVyIjoicHJvIiwiZmVhdHVyZXMiOltdfQ.invalid_signature_here";

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/deactivate")
                .header("Authorization", format!("Bearer {}", fake_jwt))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail - either bad request (parse error) or unauthorized (invalid signature)
    assert!(
        response.status() == axum::http::StatusCode::UNAUTHORIZED
            || response.status() == axum::http::StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn test_deactivate_device_not_found_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;

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
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_jwt(&state, &project, &product, &license.id, &device);

        // Delete the device before trying to deactivate
        queries::delete_device(&conn, &device.id).unwrap();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/deactivate")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_deactivate_already_revoked_jti_returns_forbidden() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;

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
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_jwt(&state, &project, &product, &license.id, &device);

        // Pre-revoke the JTI (but keep the device record)
        queries::add_revoked_jti(&conn, &license.id, &device.jti).unwrap();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/deactivate")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_deactivate_machine_type_device() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;

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
        // Create a machine-type device
        let device = create_test_device(&conn, &license.id, "machine-id-hash", DeviceType::Machine);

        // Create JWT with machine device type
        let claims = LicenseClaims {
            license_exp: Some(future_timestamp(365)),
            updates_exp: Some(future_timestamp(180)),
            tier: product.tier.clone(),
            features: product.features.clone(),
            device_id: device.device_id.clone(),
            device_type: "machine".to_string(),
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

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/deactivate")
                .header("Authorization", format!("Bearer {}", token))
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

    assert_eq!(json["deactivated"], true);
}
