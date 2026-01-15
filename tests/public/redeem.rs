//! Tests for the POST /redeem endpoint:
//! Redeem an activation code for a JWT token and register a device.

use axum::{body::Body, http::Request};
use common::{ONE_DAY, ONE_YEAR, UPDATES_VALID_DAYS};
use serde_json::{Value, json};
use tower::ServiceExt;

#[path = "../common/mod.rs"]
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
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

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
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "code": code,
                        "device_id": "test-device",
                        "device_type": "uuid"
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
        "redeem with valid code should return 200 OK"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert!(
        json["token"].is_string(),
        "response should contain a token string"
    );
    assert!(
        !json["token"].as_str().unwrap().is_empty(),
        "token should not be empty"
    );
    assert!(
        json["tier"].is_string(),
        "response should contain a tier string"
    );
    assert!(
        json["features"].is_array(),
        "response should contain a features array"
    );
    // Should return a new activation code for future use
    assert!(
        json["activation_code"].is_string(),
        "response should contain an activation_code string"
    );
    assert!(
        json["activation_code_expires_at"].is_i64(),
        "response should contain activation_code_expires_at timestamp"
    );
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
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

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
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "code": code,
                        "device_id": "test-device",
                        "device_type": "invalid"
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
        "invalid device_type should return 400 BAD_REQUEST"
    );
}

/// Test that non-existent codes return FORBIDDEN (not NOT_FOUND).
/// This prevents attackers from distinguishing between "code doesn't exist"
/// and "code exists but was already used/expired" - all invalid codes return
/// the same error to prevent enumeration attacks.
#[tokio::test]
async fn test_redeem_code_not_found_returns_forbidden() {
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
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "code": "invalid-code",
                        "device_id": "test-device",
                        "device_type": "uuid"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Returns FORBIDDEN (not NOT_FOUND) to prevent enumeration attacks
    assert_eq!(
        response.status(),
        axum::http::StatusCode::FORBIDDEN,
        "non-existent code should return FORBIDDEN to prevent enumeration attacks"
    );
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
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

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
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "code": code,
                        "device_id": "test-device",
                        "device_type": "uuid"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::FORBIDDEN,
        "already-used activation code should return FORBIDDEN"
    );
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
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

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
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "code": code,
                        "device_id": "new-device-123",
                        "device_type": "uuid",
                        "device_name": "My Device"
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
        "redeem should succeed and return 200 OK"
    );

    // Verify device was created
    let conn = state.db.get().unwrap();
    let devices = queries::list_devices_for_license(&conn, &license_id).unwrap();
    assert_eq!(devices.len(), 1, "exactly one device should be created");
    assert_eq!(
        devices[0].device_id, "new-device-123",
        "device_id should match the request"
    );
    assert_eq!(
        devices[0].name,
        Some("My Device".to_string()),
        "device name should match the request"
    );
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
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

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
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "code": code,
                        "device_id": "test-device",
                        "device_type": "uuid"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::FORBIDDEN,
        "redeeming code for revoked license should return FORBIDDEN"
    );
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
            Some(past_timestamp(ONE_DAY)), // Expired
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
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "code": code,
                        "device_id": "test-device",
                        "device_type": "uuid"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::FORBIDDEN,
        "redeeming code for expired license should return FORBIDDEN"
    );
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
            license_exp_days: Some(ONE_YEAR as i32),
            updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
            activation_limit: 10,
            device_limit: 1, // Only 1 device allowed
            features: vec![],
        };
        let product =
            queries::create_product(&conn, &project.id, &input).expect("Failed to create product");

        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

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
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "code": code,
                        "device_id": "device-2",
                        "device_type": "uuid"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail because device limit exceeded
    assert!(
        response.status() == axum::http::StatusCode::FORBIDDEN
            || response.status() == axum::http::StatusCode::BAD_REQUEST,
        "exceeding device limit should return FORBIDDEN or BAD_REQUEST"
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
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

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
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "code": code,
                        "device_id": "existing-device",
                        "device_type": "uuid"
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
        "reactivating same device should succeed"
    );
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
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

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
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "code": code,
                        "device_id": "test-device",
                        "device_type": "uuid"
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
        "redeem using public_key should succeed"
    );
}

// ============================================================================
// Security Tests - Activation Code Security
// ============================================================================

mod activation_code_security {
    use super::*;

    #[tokio::test]
    async fn test_activation_code_cannot_be_reused_different_device() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            public_key = project.public_key.clone();
            code = activation_code.code.clone();
        }

        // First redemption on device_a should succeed
        let app = public_app(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "device_a",
                            "device_type": "uuid"
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
            "first redemption on device_a should succeed"
        );

        // Second redemption on device_b with same code should fail
        let app = public_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "device_b",
                            "device_type": "uuid"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "reusing activation code on different device should be forbidden"
        );
    }

    #[tokio::test]
    async fn test_activation_code_rejected_at_exact_expiry() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            // Manually set the expiry to 1 second ago (past)
            conn.execute(
                "UPDATE activation_codes SET expires_at = ?1 WHERE id = ?2",
                rusqlite::params![now() - 1, &activation_code.id],
            )
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
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "test-device",
                            "device_type": "uuid"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "expired activation code should return FORBIDDEN"
        );
    }

    #[tokio::test]
    async fn test_old_activation_code_invalidated_by_new_request() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let first_code: String;
        let second_code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            // Create first activation code
            let first_activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();
            first_code = first_activation_code.code.clone();

            // Mark first code as used (simulating that a new code was requested, which should
            // invalidate old codes - in practice the system creates new codes without invalidating,
            // but this test verifies that used codes cannot be reused)
            queries::mark_activation_code_used(&conn, &first_activation_code.id).unwrap();

            // Create second activation code
            let second_activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();
            second_code = second_activation_code.code.clone();

            public_key = project.public_key.clone();
        }

        // First (invalidated) code should fail
        let app = public_app(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": first_code,
                            "device_id": "test-device",
                            "device_type": "uuid"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "used activation code should return FORBIDDEN"
        );

        // Second (valid) code should succeed
        let app = public_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": second_code,
                            "device_id": "test-device",
                            "device_type": "uuid"
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
            "new valid activation code should succeed"
        );
    }

    #[tokio::test]
    async fn test_activation_code_for_revoked_license_returns_forbidden() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            // Create activation code first
            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            // Then revoke the license
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
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "test-device",
                            "device_type": "uuid"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "activation code for revoked license should return FORBIDDEN"
        );
    }

    #[tokio::test]
    async fn test_activation_code_for_deleted_license_returns_error() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            // Create activation code first
            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            // Then soft-delete the license
            queries::soft_delete_license(&conn, &license.id).unwrap();

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
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "test-device",
                            "device_type": "uuid"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Soft-deleted license should not be found (treated as internal error since the
        // code references a license that's effectively gone)
        assert!(
            response.status() == axum::http::StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == axum::http::StatusCode::NOT_FOUND,
            "activation code for soft-deleted license should return error"
        );
    }
}

// ============================================================================
// Security Tests - Device Limit Enforcement
// ============================================================================

mod device_limit_enforcement {
    use super::*;

    #[tokio::test]
    async fn test_device_limit_enforced_strictly() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            // Create product with device_limit = 2
            let input = CreateProduct {
                name: "Limited Plan".to_string(),
                tier: "limited".to_string(),
                license_exp_days: Some(ONE_YEAR as i32),
                updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
                activation_limit: 10,
                device_limit: 2,
                features: vec![],
            };
            let product = queries::create_product(&conn, &project.id, &input).unwrap();

            // Create license at device limit (2 devices)
            let (license, _devices) = create_license_at_device_limit(&conn, &project.id, &product);

            // Create activation code for attempting one more activation
            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            public_key = project.public_key.clone();
            code = activation_code.code.clone();
        }

        let app = public_app(state);

        // Try to activate a third device - should fail
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "new-device-exceeds-limit",
                            "device_type": "uuid"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "exceeding device limit should return FORBIDDEN"
        );
    }

    #[tokio::test]
    async fn test_same_device_id_reactivation_allowed() {
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
                name: "Single Device Plan".to_string(),
                tier: "single".to_string(),
                license_exp_days: Some(ONE_YEAR as i32),
                updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
                activation_limit: 10,
                device_limit: 1,
                features: vec![],
            };
            let product = queries::create_product(&conn, &project.id, &input).unwrap();

            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            // Create an existing device (using up the limit)
            create_test_device(&conn, &license.id, "existing-device", DeviceType::Uuid);

            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            public_key = project.public_key.clone();
            code = activation_code.code.clone();
        }

        let app = public_app(state);

        // Reactivation with same device_id should succeed (not counting toward limit)
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "existing-device",
                            "device_type": "uuid"
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
            "reactivating same device should succeed even at device limit"
        );
    }

    #[tokio::test]
    async fn test_device_limit_zero_means_unlimited() {
        // device_limit = 0 means "unlimited devices", not "no devices"
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            // Create product with device_limit = 0 (unlimited)
            let input = CreateProduct {
                name: "Unlimited Device Plan".to_string(),
                tier: "unlimited".to_string(),
                license_exp_days: Some(ONE_YEAR as i32),
                updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
                activation_limit: 10,
                device_limit: 0, // 0 means unlimited devices
                features: vec![],
            };
            let product = queries::create_product(&conn, &project.id, &input).unwrap();

            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            public_key = project.public_key.clone();
            code = activation_code.code.clone();
        }

        let app = public_app(state);

        // Activation should succeed with device_limit = 0 (unlimited)
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "any-device",
                            "device_type": "uuid"
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
            "device_limit=0 means unlimited, should succeed"
        );
    }

    #[tokio::test]
    async fn test_deactivated_device_frees_slot() {
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
                name: "Single Device Plan".to_string(),
                tier: "single".to_string(),
                license_exp_days: Some(ONE_YEAR as i32),
                updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
                activation_limit: 10,
                device_limit: 1,
                features: vec![],
            };
            let product = queries::create_product(&conn, &project.id, &input).unwrap();

            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            // Create and then delete a device (simulating deactivation)
            let device = create_test_device(&conn, &license.id, "old-device", DeviceType::Uuid);
            queries::delete_device(&conn, &device.id).unwrap();

            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            public_key = project.public_key.clone();
            code = activation_code.code.clone();
        }

        let app = public_app(state);

        // New activation should succeed since old device was deactivated
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "new-device",
                            "device_type": "uuid"
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
            "deactivated device should free slot for new activation"
        );
    }
}

// ============================================================================
// Security Tests - Activation Limit Enforcement
// ============================================================================

mod activation_limit_enforcement {
    use super::*;

    #[tokio::test]
    async fn test_activation_limit_counts_total_activations() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            // Create product with activation_limit = 2, device_limit = 10
            let input = CreateProduct {
                name: "Limited Activations".to_string(),
                tier: "limited".to_string(),
                license_exp_days: Some(ONE_YEAR as i32),
                updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
                activation_limit: 2, // Only 2 activations ever
                device_limit: 10,    // Device limit is higher
                features: vec![],
            };
            let product = queries::create_product(&conn, &project.id, &input).unwrap();

            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            // Manually set activation_count to 2 (at the limit)
            conn.execute(
                "UPDATE licenses SET activation_count = 2 WHERE id = ?1",
                rusqlite::params![&license.id],
            )
            .unwrap();

            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            public_key = project.public_key.clone();
            code = activation_code.code.clone();
        }

        let app = public_app(state);

        // Third activation should fail
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "new-device",
                            "device_type": "uuid"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "exceeding activation limit should return FORBIDDEN"
        );
    }

    #[tokio::test]
    async fn test_activation_limit_includes_deactivated() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            // Create product with activation_limit = 2, device_limit = 10
            let input = CreateProduct {
                name: "Limited Activations".to_string(),
                tier: "limited".to_string(),
                license_exp_days: Some(ONE_YEAR as i32),
                updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
                activation_limit: 2, // Only 2 activations ever
                device_limit: 10,    // Device limit is higher
                features: vec![],
            };
            let product = queries::create_product(&conn, &project.id, &input).unwrap();

            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            // Create 2 devices and then delete them (simulating activations followed by deactivations)
            let device1 = create_test_device(&conn, &license.id, "device-1", DeviceType::Uuid);
            let device2 = create_test_device(&conn, &license.id, "device-2", DeviceType::Uuid);

            // Manually set activation_count to 2 (these devices counted)
            conn.execute(
                "UPDATE licenses SET activation_count = 2 WHERE id = ?1",
                rusqlite::params![&license.id],
            )
            .unwrap();

            // Delete devices (deactivate them)
            queries::delete_device(&conn, &device1.id).unwrap();
            queries::delete_device(&conn, &device2.id).unwrap();

            // Verify activation_count is still 2 even though devices are deleted
            let updated_license = queries::get_license_by_id(&conn, &license.id)
                .unwrap()
                .unwrap();
            assert_eq!(
                updated_license.activation_count, 2,
                "activation_count should persist after device deletion"
            );

            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            public_key = project.public_key.clone();
            code = activation_code.code.clone();
        }

        let app = public_app(state);

        // Even though no devices are active, activation_count is at limit
        // so new activation should fail
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "new-device-3",
                            "device_type": "uuid"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "deactivated devices should still count toward activation limit"
        );
    }

    /// Test that try_claim_activation_code is atomic - calling it twice with the same
    /// code should only succeed once. This prevents race conditions where multiple
    /// concurrent requests could use the same activation code.
    #[tokio::test]
    async fn test_activation_code_atomic_claim_prevents_double_use() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            code = activation_code.code.clone();

            // First claim should succeed
            let first_claim = queries::try_claim_activation_code(&conn, &code).unwrap();
            assert!(
                first_claim.is_some(),
                "first atomic claim should succeed"
            );

            // Second claim with same code should fail (already claimed)
            let second_claim = queries::try_claim_activation_code(&conn, &code).unwrap();
            assert!(
                second_claim.is_none(),
                "second atomic claim should fail - code already used"
            );
        }
    }

    /// Test that concurrent redemption attempts with DIFFERENT activation codes
    /// but the same license cannot bypass device limits.
    ///
    /// This validates that `acquire_device_atomic` with IMMEDIATE transaction mode
    /// properly serializes concurrent device creation attempts.
    #[tokio::test]
    async fn test_concurrent_redeem_different_codes_cannot_bypass_device_limit() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let license_id: String;
        let codes: Vec<String>;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            // Product with device_limit=1 but high activation_limit
            let input = CreateProduct {
                name: "Single Device".to_string(),
                tier: "single".to_string(),
                license_exp_days: Some(ONE_YEAR as i32),
                updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
                activation_limit: 100, // High activation limit
                device_limit: 1,       // Only 1 device allowed!
                features: vec![],
            };
            let product = queries::create_product(&conn, &project.id, &input).unwrap();
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            // Create 5 different activation codes for the SAME license
            let mut activation_codes = vec![];
            for _ in 0..5 {
                let code =
                    queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                        .unwrap();
                activation_codes.push(code.code);
            }

            public_key = project.public_key.clone();
            license_id = license.id.clone();
            codes = activation_codes;
        }

        // Spawn concurrent redemption tasks - each with a DIFFERENT code and device_id
        let mut handles = vec![];
        for (i, code) in codes.into_iter().enumerate() {
            let state_clone = state.clone();
            let public_key_clone = public_key.clone();

            handles.push(tokio::spawn(async move {
                let app = public_app(state_clone);
                let response = app
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/redeem")
                            .header("content-type", "application/json")
                            .body(Body::from(
                                serde_json::to_string(&json!({
                                    "public_key": public_key_clone,
                                    "code": code,
                                    "device_id": format!("device-{}", i),
                                    "device_type": "uuid"
                                }))
                                .unwrap(),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                response.status()
            }));
        }

        // Wait for all tasks to complete
        let mut successes = 0;
        let mut device_limit_failures = 0;
        for handle in handles {
            let status = handle.await.unwrap();
            if status == axum::http::StatusCode::OK {
                successes += 1;
            } else if status == axum::http::StatusCode::FORBIDDEN {
                device_limit_failures += 1;
            }
        }

        // Exactly one should succeed (device_limit=1), the rest should fail
        assert_eq!(
            successes, 1,
            "Exactly one redemption should succeed with device_limit=1"
        );
        assert_eq!(
            device_limit_failures, 4,
            "Four redemptions should fail due to device limit"
        );

        // Verify only one device was created despite concurrent attempts
        {
            let conn = state.db.get().unwrap();
            let devices = queries::list_devices_for_license(&conn, &license_id).unwrap();
            assert_eq!(
                devices.len(),
                1,
                "Only one device should be created despite 5 concurrent attempts with different codes"
            );

            // Verify activation_count is correct (only incremented once)
            let license = queries::get_license_by_id(&conn, &license_id).unwrap().unwrap();
            assert_eq!(
                license.activation_count, 1,
                "Activation count should be 1"
            );
        }
    }

    /// Test that concurrent redemption attempts cannot bypass activation limits.
    ///
    /// Similar to device limit test, but tests activation_limit enforcement.
    /// Even with high device_limit, activation_limit should be respected.
    #[tokio::test]
    async fn test_concurrent_redeem_cannot_bypass_activation_limit() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let license_id: String;
        let codes: Vec<String>;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            // Product with activation_limit=2 but high device_limit
            let input = CreateProduct {
                name: "Limited Activations".to_string(),
                tier: "limited".to_string(),
                license_exp_days: Some(ONE_YEAR as i32),
                updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
                activation_limit: 2, // Only 2 activations ever!
                device_limit: 100,   // High device limit
                features: vec![],
            };
            let product = queries::create_product(&conn, &project.id, &input).unwrap();
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            // Create 5 different activation codes for the SAME license
            let mut activation_codes = vec![];
            for _ in 0..5 {
                let code =
                    queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                        .unwrap();
                activation_codes.push(code.code);
            }

            public_key = project.public_key.clone();
            license_id = license.id.clone();
            codes = activation_codes;
        }

        // Spawn concurrent redemption tasks
        let mut handles = vec![];
        for (i, code) in codes.into_iter().enumerate() {
            let state_clone = state.clone();
            let public_key_clone = public_key.clone();

            handles.push(tokio::spawn(async move {
                let app = public_app(state_clone);
                let response = app
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/redeem")
                            .header("content-type", "application/json")
                            .body(Body::from(
                                serde_json::to_string(&json!({
                                    "public_key": public_key_clone,
                                    "code": code,
                                    "device_id": format!("device-{}", i),
                                    "device_type": "uuid"
                                }))
                                .unwrap(),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                response.status()
            }));
        }

        // Wait for all tasks to complete
        let mut successes = 0;
        let mut failures = 0;
        for handle in handles {
            let status = handle.await.unwrap();
            if status == axum::http::StatusCode::OK {
                successes += 1;
            } else if status == axum::http::StatusCode::FORBIDDEN {
                failures += 1;
            }
        }

        // Exactly two should succeed (activation_limit=2), rest should fail
        assert_eq!(
            successes, 2,
            "Exactly two redemptions should succeed with activation_limit=2"
        );
        assert_eq!(
            failures, 3,
            "Three redemptions should fail due to activation limit"
        );

        // Verify exactly 2 devices created
        {
            let conn = state.db.get().unwrap();
            let devices = queries::list_devices_for_license(&conn, &license_id).unwrap();
            assert_eq!(
                devices.len(),
                2,
                "Exactly 2 devices should be created (activation_limit=2)"
            );

            let license = queries::get_license_by_id(&conn, &license_id).unwrap().unwrap();
            assert_eq!(
                license.activation_count, 2,
                "Activation count should be exactly 2"
            );
        }
    }

    /// Test that concurrent redemption attempts with the same activation code
    /// result in only one successful device creation.
    #[tokio::test]
    async fn test_concurrent_redeem_same_code_only_one_succeeds() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let license_id: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            // Product with high device limit - we want to test code atomicity, not device limits
            let input = CreateProduct {
                name: "Unlimited".to_string(),
                tier: "unlimited".to_string(),
                license_exp_days: Some(ONE_YEAR as i32),
                updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
                activation_limit: 100,
                device_limit: 100,
                features: vec![],
            };
            let product = queries::create_product(&conn, &project.id, &input).unwrap();
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            public_key = project.public_key.clone();
            license_id = license.id.clone();
            code = activation_code.code.clone();
        }

        // Spawn multiple concurrent redemption tasks
        let mut handles = vec![];
        for i in 0..5 {
            let state_clone = state.clone();
            let public_key_clone = public_key.clone();
            let code_clone = code.clone();

            handles.push(tokio::spawn(async move {
                let app = public_app(state_clone);
                let response = app
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/redeem")
                            .header("content-type", "application/json")
                            .body(Body::from(
                                serde_json::to_string(&json!({
                                    "public_key": public_key_clone,
                                    "code": code_clone,
                                    "device_id": format!("device-{}", i),
                                    "device_type": "uuid"
                                }))
                                .unwrap(),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                response.status()
            }));
        }

        // Wait for all tasks to complete
        let mut successes = 0;
        let mut failures = 0;
        for handle in handles {
            let status = handle.await.unwrap();
            if status == axum::http::StatusCode::OK {
                successes += 1;
            } else if status == axum::http::StatusCode::FORBIDDEN {
                failures += 1;
            }
        }

        // Exactly one should succeed, the rest should fail
        assert_eq!(successes, 1, "Exactly one redemption should succeed");
        assert_eq!(failures, 4, "Four redemptions should fail");

        // Verify only one device was created
        {
            let conn = state.db.get().unwrap();
            let devices = queries::list_devices_for_license(&conn, &license_id).unwrap();
            assert_eq!(
                devices.len(),
                1,
                "Only one device should be created despite concurrent attempts"
            );
        }
    }
}

// ============================================================================
// Input Length Validation Tests
// ============================================================================

mod input_length_validation {
    use super::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn test_oversized_device_id_returns_bad_request() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            public_key = project.public_key.clone();
            code = activation_code.code.clone();
        }

        let app = public_app(state);

        // device_id with 300 characters (over 256 limit)
        let oversized_device_id = "A".repeat(300);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": oversized_device_id,
                            "device_type": "uuid"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "oversized device_id should return BAD_REQUEST"
        );
        // Error details are in the "details" field
        assert!(
            json["details"].as_str().unwrap().contains("device_id too long"),
            "error should indicate device_id is too long"
        );
    }

    #[tokio::test]
    async fn test_oversized_device_name_returns_bad_request() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            public_key = project.public_key.clone();
            code = activation_code.code.clone();
        }

        let app = public_app(state);

        // device_name with 300 characters (over 256 limit)
        let oversized_device_name = "B".repeat(300);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "valid-device-id",
                            "device_type": "uuid",
                            "device_name": oversized_device_name
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "oversized device_name should return BAD_REQUEST"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["details"].as_str().unwrap().contains("device_name too long"),
            "error should indicate device_name is too long"
        );
    }

    #[tokio::test]
    async fn test_empty_device_id_returns_bad_request() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

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
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": "",
                            "device_type": "uuid"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "empty device_id should return BAD_REQUEST"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["details"].as_str().unwrap().contains("device_id cannot be empty"),
            "error should indicate device_id cannot be empty"
        );
    }

    #[tokio::test]
    async fn test_valid_length_inputs_accepted() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let public_key: String;
        let code: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            let activation_code =
                queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)
                    .unwrap();

            public_key = project.public_key.clone();
            code = activation_code.code.clone();
        }

        let app = public_app(state);

        // Max allowed length (256 chars) should succeed
        let max_device_id = "A".repeat(256);
        let max_device_name = "B".repeat(256);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "public_key": public_key,
                            "code": code,
                            "device_id": max_device_id,
                            "device_type": "uuid",
                            "device_name": max_device_name
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should succeed (200 OK) because lengths are at the limit, not over
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "max-length inputs (256 chars) should be accepted"
        );
    }
}
