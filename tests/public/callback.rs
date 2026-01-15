//! Tests for the GET /callback endpoint.
//!
//! The callback endpoint is where users are redirected after payment completion.
//! It returns a redirect with an activation code (NOT a JWT or license key).
//! The user must then call /redeem with the code and device info to get a JWT.

use axum::{body::Body, http::Request};
use tower::ServiceExt;

#[path = "../common/mod.rs"]
mod common;
use common::{
    complete_payment_session, create_test_license, create_test_org, create_test_payment_session,
    create_test_product, create_test_project, future_timestamp, public_app, queries,
    test_master_key, CreateProject, LICENSE_VALID_DAYS,
};
use common::create_test_app_state;

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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::NOT_FOUND,
        "callback should return 404 when session ID does not exist"
    );
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
        let session = create_test_payment_session(&conn, &product.id, None);

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
        axum::http::StatusCode::TEMPORARY_REDIRECT,
        "pending session should return temporary redirect status"
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
        "redirect URL should include status=pending for uncompleted payment"
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
            Some(future_timestamp(LICENSE_VALID_DAYS)),
        );

        // Create a payment session
        let session = create_test_payment_session(&conn, &product.id, None);

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
        axum::http::StatusCode::TEMPORARY_REDIRECT,
        "completed session should return temporary redirect status"
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
        "redirect should NOT include token - user must activate via /redeem"
    );
    assert!(
        !location.contains("license_key="),
        "redirect should NOT include license_key - email-only activation model"
    );
    assert!(
        location.contains("code="),
        "redirect should include activation code for /redeem endpoint"
    );
    assert!(
        location.contains("status=success"),
        "redirect should include status=success for completed payment"
    );
    assert!(
        location.contains("project_id="),
        "redirect should include project_id for client identification"
    );
}

#[tokio::test]
async fn test_callback_project_redirect_url() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");

        // Create project with a redirect URL configured
        let input = CreateProject {
            name: "Test Project".to_string(),
            license_key_prefix: "TEST".to_string(),
            redirect_url: Some("https://myapp.example.com/activated".to_string()),
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

        // Create license
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(LICENSE_VALID_DAYS)),
        );

        // Create a payment session (no redirect_url - uses project's)
        let session = create_test_payment_session(&conn, &product.id, None);

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
        axum::http::StatusCode::TEMPORARY_REDIRECT,
        "callback should return temporary redirect when project has custom redirect URL"
    );

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();

    // Should redirect to project's configured URL
    assert!(
        location.starts_with("https://myapp.example.com/activated"),
        "redirect should use project's configured URL, got: {}",
        location
    );

    // Should include activation code and project_id
    assert!(
        location.contains("code="),
        "redirect should include activation code for /redeem endpoint"
    );
    assert!(
        location.contains("project_id="),
        "redirect should include project_id for client identification"
    );
    assert!(
        location.contains("status=success"),
        "redirect should include status=success for completed payment"
    );
}
