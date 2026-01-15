//! Security tests for CSRF protection.
//!
//! These tests verify that the API is resistant to Cross-Site Request Forgery (CSRF) attacks.
//! The application uses Bearer token authentication (not cookies), which provides inherent
//! CSRF protection since browsers cannot automatically include custom headers in cross-origin
//! requests.
//!
//! These tests document and verify the security properties that prevent CSRF:
//! 1. State-changing endpoints require Authorization headers
//! 2. Form-encoded submissions are rejected (JSON only)
//! 3. Missing or invalid auth returns appropriate errors

#[path = "../common/mod.rs"]
mod common;

use axum::{Router, body::Body, http::Request};
use common::*;
use paycheck::db::AppState;
use paycheck::handlers;
use paycheck::models::{DeviceType, OrgMemberRole};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde_json::json;
use tower::ServiceExt;

fn org_app() -> (Router, AppState) {
    let master_key = test_master_key();

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();
    {
        let conn = pool.get().unwrap();
        paycheck::db::init_db(&conn).unwrap();
    }

    let audit_manager = SqliteConnectionManager::memory();
    let audit_pool = Pool::builder().max_size(4).build(audit_manager).unwrap();
    {
        let conn = audit_pool.get().unwrap();
        paycheck::db::init_audit_db(&conn).unwrap();
    }

    let state = AppState {
        db: pool,
        audit: audit_pool,
        base_url: "http://localhost:3000".to_string(),
        audit_log_enabled: false,
        master_key,
        email_hasher: paycheck::crypto::EmailHasher::from_bytes([0xAA; 32]),
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: std::sync::Arc::new(
            paycheck::rate_limit::ActivationRateLimiter::default(),
        ),
        email_service: std::sync::Arc::new(paycheck::email::EmailService::new(
            None,
            "test@example.com".to_string(),
        )),
        jwks_cache: std::sync::Arc::new(paycheck::jwt::JwksCache::new()),
        trusted_issuers: vec![],
    };

    let app =
        handlers::orgs::router(state.clone(), paycheck::config::RateLimitConfig::disabled())
            .with_state(state.clone());

    (app, state)
}

// ============ CSRF PROTECTION TESTS ============

/// CSRF TEST: State-changing requests without Authorization header should be rejected.
///
/// This verifies that an attacker cannot trigger state changes via cross-origin
/// form submissions or simple requests, since they cannot include custom headers.
#[tokio::test]
async fn test_create_license_without_auth_header_rejected() {
    let (app, state) = org_app();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;
    let org_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        org_id = org.id;
        project_id = project.id;
        product_id = product.id;
    }

    // Attempt to create a license WITHOUT Authorization header (simulating CSRF)
    let payload = json!({
        "product_id": product_id,
        "customer_id": "victim_customer"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/projects/{}/licenses", org_id, project_id))
                .header("content-type", "application/json")
                // NO Authorization header - simulating CSRF attack
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNAUTHORIZED,
        "Requests without Authorization header must be rejected to prevent CSRF"
    );
}

/// CSRF TEST: State-changing requests with empty Authorization header should be rejected.
#[tokio::test]
async fn test_create_license_with_empty_auth_header_rejected() {
    let (app, state) = org_app();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;
    let org_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        org_id = org.id;
        project_id = project.id;
        product_id = product.id;
    }

    let payload = json!({
        "product_id": product_id,
        "customer_id": "victim_customer"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/projects/{}/licenses", org_id, project_id))
                .header("content-type", "application/json")
                .header("authorization", "") // Empty auth header
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNAUTHORIZED,
        "Requests with empty Authorization header must be rejected"
    );
}

/// CSRF TEST: Form-encoded submissions should be rejected (JSON only).
///
/// Browsers can send form-encoded data in cross-origin POST requests without
/// triggering CORS preflight. Rejecting non-JSON content types adds defense in depth.
#[tokio::test]
async fn test_form_encoded_submission_rejected() {
    let (app, state) = org_app();
    let master_key = test_master_key();

    let project_id: String;
    let org_id: String;
    let api_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (_, _member, key) =
            create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        org_id = org.id;
        project_id = project.id;
        api_key = key;

        // Use product_id in form body
        let form_body = format!("product_id={}&customer_id=victim", product.id);

        // Drop conn before making request
        drop(conn);

        // Attempt form-encoded submission (simulating HTML form CSRF attack)
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/licenses", org_id, project_id))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("authorization", format!("Bearer {}", api_key))
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should reject with 400 or 415 (Unsupported Media Type) or 422 (Unprocessable Entity)
        let status = response.status();
        assert!(
            status == axum::http::StatusCode::BAD_REQUEST
                || status == axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE
                || status == axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "Form-encoded submissions should be rejected, got {}",
            status
        );
    }
}

/// CSRF TEST: DELETE requests without auth should be rejected.
#[tokio::test]
async fn test_delete_without_auth_rejected() {
    let (app, state) = org_app();
    let master_key = test_master_key();

    let project_id: String;
    let org_id: String;
    let license_id: String;
    let device_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(&conn, &project.id, &product.id, None);
        let device = create_test_device(&conn, &license.id, "test-device", DeviceType::Machine);

        org_id = org.id;
        project_id = project.id;
        license_id = license.id;
        device_id = device.id;
    }

    // Attempt to delete a device WITHOUT auth (simulating CSRF)
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/orgs/{}/projects/{}/licenses/{}/devices/{}",
                    org_id, project_id, license_id, device_id
                ))
                // NO Authorization header
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNAUTHORIZED,
        "DELETE requests without auth must be rejected to prevent CSRF"
    );
}

/// CSRF TEST: PUT requests without auth should be rejected.
#[tokio::test]
async fn test_put_without_auth_rejected() {
    let (app, state) = org_app();

    let org_id: String;
    let member_user_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (user, _member, _key) =
            create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Member);

        org_id = org.id;
        member_user_id = user.id;
    }

    // Attempt to update a member's role WITHOUT auth (simulating CSRF privilege escalation)
    let payload = json!({
        "role": "owner"  // Attempting to escalate to owner
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/orgs/{}/members/{}", org_id, member_user_id))
                .header("content-type", "application/json")
                // NO Authorization header
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNAUTHORIZED,
        "PUT requests without auth must be rejected to prevent CSRF privilege escalation"
    );
}

/// CSRF TEST: Revoke license without auth should be rejected.
#[tokio::test]
async fn test_revoke_license_without_auth_rejected() {
    let (app, state) = org_app();
    let master_key = test_master_key();

    let project_id: String;
    let org_id: String;
    let license_id: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(&conn, &project.id, &product.id, None);

        org_id = org.id;
        project_id = project.id;
        license_id = license.id;
    }

    // Attempt to revoke a license WITHOUT auth (simulating CSRF attack)
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/orgs/{}/projects/{}/licenses/{}/revoke",
                    org_id, project_id, license_id
                ))
                // NO Authorization header
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNAUTHORIZED,
        "License revocation without auth must be rejected to prevent CSRF"
    );
}

/// Control test: Valid auth should work (proves the endpoint functions correctly).
#[tokio::test]
async fn test_valid_auth_allows_request() {
    let (app, state) = org_app();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;
    let org_id: String;
    let api_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (_, _member, key) =
            create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

        org_id = org.id;
        project_id = project.id;
        product_id = product.id;
        api_key = key;
    }

    let payload = json!({
        "product_id": product_id,
        "customer_id": "test_customer"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/projects/{}/licenses", org_id, project_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", api_key))
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "Valid Bearer token auth should allow the request"
    );
}
