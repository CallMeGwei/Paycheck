//! Tests for the POST /buy endpoint validation logic.
//!
//! Note: These tests only cover validation errors that occur before payment
//! provider API calls. Full buy flow testing would require HTTP mocking.
//!
//! The /buy endpoint now only requires product_id. Device info is NOT required
//! since purchase ≠ activation. Users activate via /redeem/key with device info.

use axum::{body::Body, http::Request};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;
use common::*;

#[tokio::test]
async fn test_buy_product_not_found_returns_error() {
    let state = create_test_app_state();
    let app = public_app(state);

    let body = json!({
        "product_id": "nonexistent-product-id"
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
async fn test_buy_redirect_url_not_in_allowlist_returns_error() {
    let state = create_test_app_state();
    let master_key = test_master_key();

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
            email_from: None,
            email_enabled: true,
            email_webhook_url: None,
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
        product_id = product.id.clone();
    }

    let app = public_app(state);

    let body = json!({
        "product_id": product_id,
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

    let product_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        // Project has empty allowed_redirect_urls (default from create_test_project)
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        product_id = product.id.clone();
    }

    let app = public_app(state);

    let body = json!({
        "product_id": product_id,
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

    let product_id: String;

    {
        let conn = state.db.get().unwrap();
        // Create org without any payment config
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        product_id = product.id.clone();
    }

    let app = public_app(state);

    // Simple request with just product_id
    let body = json!({
        "product_id": product_id
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

    let product_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        product_id = product.id.clone();
    }

    let app = public_app(state);

    let body = json!({
        "product_id": product_id,
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
async fn test_buy_missing_product_id_returns_error() {
    let state = create_test_app_state();
    let app = public_app(state);

    // Missing product_id (the only required field now)
    let body = json!({
        "customer_id": "some-customer"
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
async fn test_buy_accepts_minimal_request() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let product_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        product_id = product.id.clone();
    }

    let app = public_app(state);

    // Minimal request - just product_id
    let body = json!({
        "product_id": product_id
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

    // Will fail on "no payment provider" but request should be accepted
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Should fail on payment provider, not on missing fields
    let details = json["details"].as_str().unwrap_or("");
    assert!(
        details.contains("payment provider") || details.contains("No payment"),
        "Should fail on payment provider, not validation, got: {}",
        details
    );
}

#[tokio::test]
async fn test_buy_accepts_optional_fields() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let product_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        // Create payment config so we get past payment config check and fail on Stripe config
        create_test_payment_config(&conn, &product.id, "stripe", Some(1999));

        product_id = product.id.clone();
    }

    let app = public_app(state);

    // Request with all optional fields
    let body = json!({
        "product_id": product_id,
        "provider": "stripe",
        "customer_id": "cust_123"
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

    // Will fail on "no payment provider" but request should be accepted
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Should fail because Stripe is not configured, not validation
    let details = json["details"].as_str().unwrap_or("");
    assert!(
        details.contains("Stripe") || details.contains("not configured"),
        "Should fail on Stripe config, got: {}",
        details
    );
}
