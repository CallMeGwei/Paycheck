//! Security tests for license expiration validation.
//!
//! These tests verify that license creation properly validates expiration days
//! to prevent creating licenses that are already expired.

#[path = "../common/mod.rs"]
mod common;

use axum::{Router, body::Body, http::Request};
use common::*;
use paycheck::db::AppState;
use paycheck::handlers;
use paycheck::models::OrgMemberRole;
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

// ============ VULNERABILITY TESTS ============

/// SECURITY TEST: Creating license with negative license_exp_days should fail.
///
/// Negative expiration days would create a license that's already expired,
/// which is confusing and could cause support issues.
///
/// Expected: 400 Bad Request
/// Actual (vulnerability): 200 OK (creates already-expired license)
#[tokio::test]
async fn test_license_negative_license_exp_days_should_fail() {
    let (app, state) = org_app();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;
    let api_key: String;
    let org_id: String;

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

    // Try to create a license with negative expiration (already expired)
    let payload = json!({
        "product_id": product_id,
        "customer_id": "test_customer",
        "license_exp_days": -10  // Negative - would be expired 10 days ago
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

    let status = response.status();

    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "SECURITY ISSUE: Creating license with negative license_exp_days should fail \
         with 400 Bad Request, but got {}. \
         Negative values create already-expired licenses.",
        status
    );
}

/// SECURITY TEST: Creating license with negative updates_exp_days should fail.
#[tokio::test]
async fn test_license_negative_updates_exp_days_should_fail() {
    let (app, state) = org_app();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;
    let api_key: String;
    let org_id: String;

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

    // Try to create a license with negative updates expiration
    let payload = json!({
        "product_id": product_id,
        "customer_id": "test_customer",
        "updates_exp_days": -5  // Negative - updates already expired 5 days ago
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

    let status = response.status();

    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "SECURITY ISSUE: Creating license with negative updates_exp_days should fail \
         with 400 Bad Request, but got {}. \
         Negative values create licenses with already-expired updates.",
        status
    );
}

/// Control test: Creating license with valid positive expiration should work.
#[tokio::test]
async fn test_license_positive_expiration_works() {
    let (app, state) = org_app();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;
    let api_key: String;
    let org_id: String;

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

    // Create license with valid positive expiration
    let payload = json!({
        "product_id": product_id,
        "customer_id": "test_customer",
        "license_exp_days": 365,
        "updates_exp_days": 180
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
        "Creating license with valid positive expiration should succeed"
    );
}

/// Control test: Creating license with null expiration (perpetual) should work.
#[tokio::test]
async fn test_license_null_expiration_perpetual_works() {
    let (app, state) = org_app();
    let master_key = test_master_key();

    let project_id: String;
    let product_id: String;
    let api_key: String;
    let org_id: String;

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

    // Create perpetual license (null expiration)
    let payload = json!({
        "product_id": product_id,
        "customer_id": "test_customer",
        "license_exp_days": null,
        "updates_exp_days": null
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
        "Creating perpetual license with null expiration should succeed"
    );
}
