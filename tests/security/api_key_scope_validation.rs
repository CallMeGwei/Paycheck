//! Security tests for API key scope validation.
//!
//! These tests verify that API key scopes are properly validated at creation time
//! to prevent creating scopes for non-existent or unauthorized resources.

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

/// SECURITY TEST: Creating API key with non-existent org_id in scope should fail.
///
/// Currently the code does NOT validate that the org_id exists, allowing
/// scopes to be created for non-existent organizations. This pollutes the
/// database with invalid scopes.
///
/// Expected: 400 Bad Request (org not found)
/// Actual (vulnerability): 200 OK (scope created for non-existent org)
#[tokio::test]
async fn test_api_key_scope_with_nonexistent_org_should_fail() {
    let (app, state) = org_app();

    let org_id: String;
    let user_id: String;
    let api_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (user, _member, key) =
            create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

        org_id = org.id;
        user_id = user.id;
        api_key = key;
    }

    // Try to create an API key with a scope for a non-existent org
    let payload = json!({
        "name": "Test Key",
        "scopes": [{
            "org_id": "non_existent_org_12345",  // This org doesn't exist
            "access": "admin"
        }]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/members/{}/api-keys", org_id, user_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", api_key))
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();

    // THE VULNERABILITY: This should return 400 Bad Request, but currently returns 200 OK
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "SECURITY VULNERABILITY: Creating API key with non-existent org_id in scope \
         should fail with 400 Bad Request, but got {}. \
         This allows database pollution with invalid scopes.",
        status
    );
}

/// SECURITY TEST: Creating API key with scope for org user is not a member of should fail.
///
/// A user should not be able to create API key scopes for organizations they
/// don't have access to. While the scope won't grant access at request time
/// (middleware checks membership), it's misleading and could cause confusion.
///
/// Expected: 400 Bad Request or 403 Forbidden (not authorized for target org)
/// Actual (vulnerability): 200 OK (scope created for unauthorized org)
#[tokio::test]
async fn test_api_key_scope_for_unauthorized_org_should_fail() {
    let (app, state) = org_app();

    let org1_id: String;
    let org2_id: String;
    let user_id: String;
    let api_key: String;

    {
        let conn = state.db.get().unwrap();

        // Create two organizations
        let org1 = create_test_org(&conn, "Org 1 - User's Org");
        let org2 = create_test_org(&conn, "Org 2 - Other Org");

        // User is only a member of org1, NOT org2
        let (user, _member, key) =
            create_test_org_member(&conn, &org1.id, "owner@test.com", OrgMemberRole::Owner);

        org1_id = org1.id;
        org2_id = org2.id;
        user_id = user.id;
        api_key = key;
    }

    // Try to create an API key with a scope for org2 (which user is NOT a member of)
    let payload = json!({
        "name": "Test Key",
        "scopes": [{
            "org_id": org2_id,  // User is NOT a member of this org
            "access": "admin"
        }]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/members/{}/api-keys", org1_id, user_id))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", api_key))
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();

    // THE VULNERABILITY: This should return 400/403, but currently returns 200 OK
    assert!(
        status == axum::http::StatusCode::BAD_REQUEST
            || status == axum::http::StatusCode::FORBIDDEN,
        "SECURITY VULNERABILITY: Creating API key with scope for org user is not a member of \
         should fail with 400 or 403, but got {}. \
         Users should only be able to create scopes for orgs they have access to.",
        status
    );
}

/// Control test: Creating API key with valid scope for user's own org should work.
#[tokio::test]
async fn test_api_key_scope_for_own_org_works() {
    let (app, state) = org_app();

    let org_id: String;
    let user_id: String;
    let api_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let (user, _member, key) =
            create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

        org_id = org.id;
        user_id = user.id;
        api_key = key;
    }

    // Create an API key with a scope for the user's own org
    let payload = json!({
        "name": "Test Key",
        "scopes": [{
            "org_id": org_id,  // User IS a member of this org
            "access": "admin"
        }]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/members/{}/api-keys", org_id, user_id))
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
        "Creating API key with scope for user's own org should succeed"
    );
}
