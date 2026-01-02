//! Tests for the POST /buy endpoint validation logic.
//!
//! Note: These tests only cover validation errors that occur before payment
//! provider API calls. Full buy flow testing would require HTTP mocking.

use axum::{body::Body, http::Request};
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::*;

#[tokio::test]
async fn test_buy_invalid_device_type_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        project_id = project.id.clone();
        product_id = product.id.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "product_id": product_id,
        "device_id": "test-device",
        "device_type": "invalid" // Invalid!
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Error details should mention device_type
    let details = json["details"].as_str().unwrap_or("");
    assert!(
        details.contains("device_type"),
        "Error details should mention device_type, got: {}",
        details
    );
}

#[tokio::test]
async fn test_buy_project_not_found_returns_error() {
    let state = create_test_app_state();
    let app = public_app(state);

    let body = json!({
        "project_id": "nonexistent-project-id",
        "product_id": "some-product-id",
        "device_id": "test-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_buy_product_not_found_returns_error() {
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
        "product_id": "nonexistent-product-id",
        "device_id": "test-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_buy_product_project_mismatch_returns_not_found() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project1_id: String;
    let project2_product_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");

        // Create two projects
        let project1 = create_test_project(&conn, &org.id, "Project 1", &master_key);
        let project2 = create_test_project(&conn, &org.id, "Project 2", &master_key);

        // Create product in project2
        let product2 = create_test_product(&conn, &project2.id, "Pro Plan", "pro");

        project1_id = project1.id.clone();
        project2_product_id = product2.id.clone();
    }

    let app = public_app(state);

    // Try to buy project2's product with project1's ID
    let body = json!({
        "project_id": project1_id,
        "product_id": project2_product_id,
        "device_id": "test-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Returns 404 to mask that product exists in another project
    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_buy_redirect_url_not_in_allowlist_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");

        // Create project with allowed redirect URLs
        let input = CreateProject {
            name: "Test Project".to_string(),
            domain: "testproject.example.com".to_string(),
            license_key_prefix: "TEST".to_string(),
            allowed_redirect_urls: vec!["https://allowed.example.com".to_string()],
        };
        let (private_key, public_key) = paycheck::jwt::generate_keypair();
        let project = queries::create_project(
            &conn,
            &org.id,
            &input,
            &private_key,
            &public_key,
            &master_key,
        )
        .unwrap();

        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        project_id = project.id.clone();
        product_id = product.id.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "product_id": product_id,
        "device_id": "test-device",
        "device_type": "uuid",
        "redirect": "https://notallowed.example.com" // Not in allowlist!
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Error details should mention allowed redirect
    let details = json["details"].as_str().unwrap_or("");
    assert!(
        details.contains("allowed redirect") || details.contains("Redirect URL"),
        "Error details should mention redirect URL, got: {}",
        details
    );
}

#[tokio::test]
async fn test_buy_redirect_url_with_empty_allowlist_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        // Project has empty allowed_redirect_urls (default from create_test_project)
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        project_id = project.id.clone();
        product_id = product.id.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "product_id": product_id,
        "device_id": "test-device",
        "device_type": "uuid",
        "redirect": "https://someurl.example.com"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Error details should mention no allowed redirect
    let details = json["details"].as_str().unwrap_or("");
    assert!(
        details.contains("no allowed redirect") || details.contains("Redirect URL"),
        "Error details should mention redirect URL, got: {}",
        details
    );
}

#[tokio::test]
async fn test_buy_no_payment_provider_configured_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;

    {
        let conn = state.db.get().unwrap();
        // Create org without any payment config
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        project_id = project.id.clone();
        product_id = product.id.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "product_id": product_id,
        "device_id": "test-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Error details should mention payment provider
    let details = json["details"].as_str().unwrap_or("");
    assert!(
        details.contains("payment provider") || details.contains("No payment"),
        "Error details should mention payment provider, got: {}",
        details
    );
}

#[tokio::test]
async fn test_buy_invalid_provider_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        project_id = project.id.clone();
        product_id = product.id.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "product_id": product_id,
        "device_id": "test-device",
        "device_type": "uuid",
        "provider": "invalid_provider"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_buy_missing_required_fields_returns_error() {
    let state = create_test_app_state();
    let app = public_app(state);

    // Missing project_id
    let body = json!({
        "product_id": "some-product",
        "device_id": "test-device",
        "device_type": "uuid"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_buy_uuid_device_type_accepted() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        project_id = project.id.clone();
        product_id = product.id.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "product_id": product_id,
        "device_id": "test-device",
        "device_type": "uuid" // Valid
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Will fail on "no payment provider" but NOT on device_type
    // This confirms uuid is a valid device_type
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Should fail on payment provider, not device_type
    let details = json["details"].as_str().unwrap_or("");
    assert!(
        !details.contains("device_type"),
        "uuid should be a valid device_type, got error: {}",
        details
    );
}

#[tokio::test]
async fn test_buy_machine_device_type_accepted() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        project_id = project.id.clone();
        product_id = product.id.clone();
    }

    let app = public_app(state);

    let body = json!({
        "project_id": project_id,
        "product_id": product_id,
        "device_id": "test-device",
        "device_type": "machine" // Valid
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Will fail on "no payment provider" but NOT on device_type
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    let details = json["details"].as_str().unwrap_or("");
    assert!(
        !details.contains("device_type"),
        "machine should be a valid device_type, got error: {}",
        details
    );
}
