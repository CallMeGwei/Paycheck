//! Tests for the GET /callback endpoint.
//!
//! The callback endpoint is where users are redirected after payment completion.
//! It returns a redirect with an activation code (NOT a JWT or license key).
//! The user must then call /redeem with the code and device info to get a JWT.

use axum::{body::Body, http::Request};
use tower::ServiceExt;

mod common;
use common::*;

#[tokio::test]
async fn test_callback_session_not_found_returns_error() {
    let state = create_test_app_state();
    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/callback?session=nonexistent-session-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_callback_pending_session_redirects_with_pending_status() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        // Create a payment session that's NOT completed
        let session = create_test_payment_session(&conn, &product.id, None, None);

        session_id = session.id.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/callback?session={}", session_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should redirect
    assert_eq!(
        response.status(),
        axum::http::StatusCode::TEMPORARY_REDIRECT
    );

    // Check redirect location contains status=pending
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        location.contains("status=pending"),
        "Redirect should include status=pending"
    );
}

#[tokio::test]
async fn test_callback_completed_session_redirects_with_activation_code() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        // Create license (no device - that's created at activation time)
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );

        // Create a payment session
        let session = create_test_payment_session(&conn, &product.id, None, None);

        // Complete the session (simulating webhook completion)
        complete_payment_session(&conn, &session.id, &license.id);

        session_id = session.id.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/callback?session={}", session_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should redirect
    assert_eq!(
        response.status(),
        axum::http::StatusCode::TEMPORARY_REDIRECT
    );

    // Check redirect location contains required params
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();

    // No token or license_key - user must activate via /redeem
    assert!(
        !location.contains("token="),
        "Callback should NOT include token (user must activate via /redeem)"
    );
    assert!(
        !location.contains("license_key="),
        "Callback should NOT include license_key (email-only activation)"
    );
    assert!(location.contains("code="), "Redirect should include activation code");
    assert!(
        location.contains("status=success"),
        "Redirect should include status=success"
    );
    assert!(
        location.contains("project_id="),
        "Redirect should include project_id"
    );
}

#[tokio::test]
async fn test_callback_third_party_redirect() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        // Create license
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(365)),
        );

        // Create a payment session WITH a third-party redirect URL
        let session = create_test_payment_session(
            &conn,
            &product.id,
            None,
            Some("https://myapp.example.com/activated"),
        );

        // Complete the session
        complete_payment_session(&conn, &session.id, &license.id);

        session_id = session.id.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/callback?session={}", session_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::TEMPORARY_REDIRECT
    );

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();

    // Should redirect to custom URL
    assert!(
        location.starts_with("https://myapp.example.com/activated"),
        "Should redirect to custom URL"
    );

    // Should include activation code and project_id
    assert!(location.contains("code="), "Should include activation code");
    assert!(location.contains("project_id="), "Should include project_id");
    assert!(location.contains("status=success"), "Should include success status");
}
