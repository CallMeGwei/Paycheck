//! Tests for the POST /buy endpoint validation logic.
//!
//! Note: These tests only cover validation errors that occur before payment
//! provider API calls. Full buy flow testing would require HTTP mocking.
//!
//! The /buy endpoint now only requires product_id. Device info is NOT required
//! since purchase ≠ activation. Users activate via /redeem/key with device info.
//! Redirect URL is configured per-project, not per-request.

use axum::{body::Body, http::Request};
use serde_json::{Value, json};
use tower::ServiceExt;

#[path = "../common/mod.rs"]
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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::NOT_FOUND,
        "buy with nonexistent product_id should return 404 NOT_FOUND"
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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "buy without configured payment provider should return 400 BAD_REQUEST"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Error details should mention payment provider
    let details = json["details"].as_str().unwrap_or("");
    assert!(
        details.contains("payment provider") || details.contains("No payment"),
        "error details should mention missing payment provider, got: {}",
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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "buy with invalid provider name should return 400 BAD_REQUEST"
    );
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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "buy without product_id should return 400 BAD_REQUEST"
    );
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
    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "minimal buy request should pass validation but fail on missing payment provider"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Should fail on payment provider, not on missing fields
    let details = json["details"].as_str().unwrap_or("");
    assert!(
        details.contains("payment provider") || details.contains("No payment"),
        "should fail on payment provider config, not request validation, got: {}",
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
    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "buy with optional fields should pass validation but fail on missing Stripe config"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // Should fail because Stripe is not configured, not validation
    let details = json["details"].as_str().unwrap_or("");
    assert!(
        details.contains("Stripe") || details.contains("not configured"),
        "should fail on Stripe configuration, not request validation, got: {}",
        details
    );
}
