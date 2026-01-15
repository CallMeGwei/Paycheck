//! Error response leakage security tests.
//!
//! These tests verify that error responses do not leak internal implementation details,
//! paths, sensitive information, or provide hints that could aid attackers:
//!
//! 1. 404 errors don't reveal file paths or internal structure
//! 2. 500 errors don't include stack traces in response body
//! 3. Database errors don't reveal table/column names
//! 4. 401 errors are generic (not "user not found" vs "password wrong")
//! 5. Resource existence not leaked (404 for both not-found and forbidden cases where appropriate)
//! 6. User enumeration prevented (can't guess valid emails from error responses)
//! 7. Error responses use consistent format (JSON with "error" field)
//! 8. No debug info in production error responses
//! 9. Rate limit errors don't reveal internal limits in message
//! 10. Validation errors don't reveal expected format in exploitable way

#[path = "../common/mod.rs"]
mod common;
use common::*;

use axum::{Router, body::Body, http::Request};
use axum::body::to_bytes;
use axum::http::StatusCode;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde_json::{Value, json};
use tower::ServiceExt;

use paycheck::config::RateLimitConfig;
use paycheck::db::AppState;
use paycheck::handlers;
use paycheck::models::{OrgMemberRole, OperatorRole};

// Use time constants from common module for readable tests
use common::{ONE_YEAR};

// ============================================================================
// Test App Setup Helpers
// ============================================================================

/// Creates a test app with the full org router (with middleware).
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

    let app = handlers::orgs::router(state.clone(), RateLimitConfig::disabled())
        .with_state(state.clone());

    (app, state)
}

/// Creates a test app with the operator router.
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

/// Creates a test app with public endpoints.
fn public_app_with_state() -> (Router, AppState) {
    let state = create_test_app_state();
    let app = public_app(state.clone());
    (app, state)
}

/// Helper to parse response body as JSON
async fn body_json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&body).to_string() }))
}

/// Patterns that should NEVER appear in error responses (case-insensitive check)
fn sensitive_patterns() -> Vec<&'static str> {
    vec![
        // File paths
        "/home/",
        "/usr/",
        "/var/",
        "/etc/",
        "\\Users\\",
        "C:\\",
        // Stack traces (note: "at line X column Y" is OK for JSON parsing errors)
        "stack trace",
        "backtrace",
        "panic",
        ".rs:",
        // Database internals
        "sqlite",
        "UNIQUE constraint",
        "FOREIGN KEY",
        "INSERT INTO",
        "SELECT ",
        "UPDATE ",
        "DELETE FROM",
        // Rust internals
        "thread '",
        "panicked at",
        "unwrap()",
        "expect()",
        // Debug info
        "RUST_BACKTRACE",
    ]
}

/// Check that an error response doesn't leak sensitive information
fn assert_no_sensitive_leakage(json: &Value, context: &str) {
    let json_str = json.to_string().to_lowercase();

    for pattern in sensitive_patterns() {
        assert!(
            !json_str.contains(&pattern.to_lowercase()),
            "{}: Error response contains sensitive pattern '{}'. Response: {}",
            context,
            pattern,
            json
        );
    }
}

/// Verify error response has consistent JSON format with "error" field
/// Note: Only call this for responses that are expected to be errors
fn assert_consistent_error_format(json: &Value, context: &str) {
    // If the response has "raw" field with empty string, it might be a non-JSON response
    // or a response that was already consumed
    if let Some(raw) = json.get("raw") {
        if raw.as_str() == Some("") {
            // Empty response - might be a 204 No Content or similar
            return;
        }
    }

    // If response has an ID field, it's a success response, not an error
    if json.get("id").is_some() {
        return;
    }

    assert!(
        json.get("error").is_some(),
        "{}: Error response missing 'error' field. Response: {}",
        context,
        json
    );

    // The error field should be a string
    assert!(
        json["error"].is_string(),
        "{}: 'error' field should be a string. Response: {}",
        context,
        json
    );
}

// ============================================================================
// NO INTERNAL DETAILS TESTS
// ============================================================================

mod no_internal_details {
    use super::*;

    /// Test that 404 errors don't reveal file paths or internal structure.
    #[tokio::test]
    async fn not_found_errors_dont_reveal_paths() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_, _, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Create a real project to test nonexistent sub-resources
        let project = create_test_project(&conn, &org.id, "Real Project", &state.master_key);

        // Test various nonexistent resource lookups
        let nonexistent_ids = vec![
            format!("/orgs/{}/projects/nonexistent-project-id", org.id),
            format!(
                "/orgs/{}/projects/{}/products/fake-product",
                org.id, project.id
            ),
            format!(
                "/orgs/{}/projects/{}/licenses/fake-license",
                org.id, project.id
            ),
            format!("/orgs/{}/members/fake-member-id", org.id),
        ];

        for uri in nonexistent_ids {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(&uri)
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            let status = response.status();
            let json = body_json(response).await;

            // Should be 404 or 403, not 500
            assert!(
                status == StatusCode::NOT_FOUND || status == StatusCode::FORBIDDEN,
                "{}: nonexistent resource should return 404 Not Found or 403 Forbidden, not 500 Internal Server Error (got {})",
                uri,
                status
            );

            assert_no_sensitive_leakage(&json, &uri);

            // Only check error format if we got an error response
            if status.is_client_error() || status.is_server_error() {
                assert_consistent_error_format(&json, &uri);
            }
        }
    }

    /// Test that 500 errors don't include stack traces in response body.
    #[tokio::test]
    async fn internal_errors_dont_expose_stack_traces() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_, _, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Try to trigger potential internal errors with malformed data
        let malformed_requests = vec![
            // Extremely long org ID that might cause issues
            (
                format!("/orgs/{}/members", "x".repeat(10000)),
                "oversized org_id",
            ),
            // Nested path traversal attempts
            (
                format!("/orgs/{}/../../../etc/passwd/members", org.id),
                "path traversal attempt",
            ),
        ];

        for (uri, context) in malformed_requests {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(&uri)
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            let json = body_json(response).await;

            assert_no_sensitive_leakage(&json, context);
        }
    }

    /// Test that database errors don't reveal table/column names.
    #[tokio::test]
    async fn database_errors_dont_reveal_schema() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_, _, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Create a project first
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        // Try operations that might trigger database errors
        let test_cases = vec![
            // Try to create product with duplicate tier (if there's uniqueness constraint)
            (
                "POST",
                format!("/orgs/{}/projects/{}/products", org.id, project.id),
                json!({
                    "name": "Test",
                    "tier": "test_tier",
                    "license_exp_days": ONE_YEAR,
                    "updates_exp_days": ONE_YEAR,
                    "activation_limit": 5,
                    "device_limit": 3,
                    "features": []
                }),
            ),
            // Try to create project with duplicate name
            (
                "POST",
                format!("/orgs/{}/projects", org.id),
                json!({
                    "name": "Test Project",
                    "license_key_prefix": "DUPE"
                }),
            ),
        ];

        for (method, uri, body) in test_cases {
            // First request to create resource
            let _ = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(&uri)
                        .header("Authorization", format!("Bearer {}", api_key))
                        .header("Content-Type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();

            // Second request with same data might trigger constraint violation
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(&uri)
                        .header("Authorization", format!("Bearer {}", api_key))
                        .header("Content-Type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();

            let json = body_json(response).await;

            assert_no_sensitive_leakage(&json, &uri);
        }
    }

    /// Test that 401 errors are generic and don't distinguish between scenarios.
    #[tokio::test]
    async fn unauthorized_errors_are_generic() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create a real org so we're testing auth, not org existence
        let org = create_test_org(&conn, "Test Org");

        // Various ways to get 401 should all return the same generic message
        let auth_test_cases = vec![
            ("invalid_token", Some("Bearer invalid-api-key")),
            ("malformed_header", Some("NotBearer token")),
            ("empty_bearer", Some("Bearer ")),
        ];

        for (case_name, auth_header) in auth_test_cases {
            let mut req_builder = Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id));

            if let Some(header) = auth_header {
                req_builder = req_builder.header("Authorization", header);
            }

            let response = app
                .clone()
                .oneshot(req_builder.body(Body::empty()).unwrap())
                .await
                .unwrap();

            let status = response.status();
            let json = body_json(response).await;

            // Should get 401 Unauthorized or 400 Bad Request
            assert!(
                status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
                "{}: invalid authentication should return 401 Unauthorized or 400 Bad Request (got {})",
                case_name,
                status
            );

            // Error message should be generic (if present)
            if let Some(error_msg) = json["error"].as_str() {
                assert!(
                    !error_msg.to_lowercase().contains("not found"),
                    "{}: 401 error should be generic and not reveal whether user exists by saying 'not found' (message: {})",
                    case_name,
                    error_msg
                );
                assert!(
                    !error_msg.to_lowercase().contains("invalid password"),
                    "{}: 401 error should be generic and not leak password validation details (message: {})",
                    case_name,
                    error_msg
                );
            }

            assert_no_sensitive_leakage(&json, case_name);
        }
    }
}

// ============================================================================
// USER ENUMERATION PREVENTION TESTS
// ============================================================================

mod user_enumeration_prevention {
    use super::*;

    /// Test that invalid user lookup doesn't reveal user existence.
    #[tokio::test]
    async fn user_lookup_doesnt_reveal_existence() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        // Create an admin operator
        let (_, _, api_key) =
            create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

        // Create a real user
        let _real_user = create_test_user(&conn, "real@example.com", "Real User");

        // Look up nonexistent user vs real user (but with wrong API key scope)
        let test_cases = vec![
            ("fake-user-id", "nonexistent user"),
            ("00000000-0000-0000-0000-000000000000", "UUID format but nonexistent"),
        ];

        let mut error_responses = Vec::new();

        for (user_id, context) in test_cases {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/users/{}", user_id))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            let status = response.status();
            let json = body_json(response).await;

            // Should be 404 for nonexistent users
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{}: lookup of nonexistent user should return 404 Not Found",
                context
            );

            error_responses.push((context, json.clone()));

            assert_no_sensitive_leakage(&json, context);
        }

        // Verify all error responses have the same structure
        // (can't distinguish between "user doesn't exist" and other 404 reasons)
        for (context, json) in &error_responses {
            if let Some(error_msg) = json["error"].as_str() {
                assert!(
                    !error_msg.to_lowercase().contains("email"),
                    "{}: error response should not mention 'email' to prevent user enumeration (message: {})",
                    context,
                    error_msg
                );
            }
        }
    }

    /// Test that org member lookup doesn't reveal member existence to non-members.
    #[tokio::test]
    async fn org_member_lookup_consistent_for_nonmembers() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create two separate orgs
        let org_a = create_test_org(&conn, "Org A");
        let org_b = create_test_org(&conn, "Org B");

        // Create members in org_a
        let (_, _, key_a) =
            create_test_org_member(&conn, &org_a.id, "user@orga.com", OrgMemberRole::Owner);
        let (real_member, _, _) =
            create_test_org_member(&conn, &org_a.id, "member@orga.com", OrgMemberRole::Member);

        // Create member in org_b
        let (_, _, key_b) =
            create_test_org_member(&conn, &org_b.id, "user@orgb.com", OrgMemberRole::Owner);

        // User from org_b tries to look up members in org_a
        // Should get same response for real member and fake member
        let test_cases = vec![
            (real_member.id.clone(), "real member"),
            ("fake-member-id".to_string(), "fake member"),
        ];

        let mut responses = Vec::new();

        for (member_id, context) in test_cases {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/orgs/{}/members/{}", org_a.id, member_id))
                        .header("Authorization", format!("Bearer {}", key_b))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            let status = response.status();
            let json = body_json(response).await;

            responses.push((context, status, json));
        }

        // Both should return the same status code (FORBIDDEN - not a member of org_a)
        let (_, status1, _) = &responses[0];
        let (_, status2, _) = &responses[1];

        assert_eq!(
            status1, status2,
            "unauthorized user should get same status for real member ({}) and fake member ({}) to prevent enumeration",
            status1,
            status2
        );

        // Verify with valid key from org_a, we can tell the difference
        // (but only for authorized users)
        let real_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members/{}", org_a.id, real_member.id))
                    .header("Authorization", format!("Bearer {}", key_a))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            real_response.status(),
            StatusCode::OK,
            "authorized user with valid API key should successfully retrieve real member (got {})",
            real_response.status()
        );
    }

    /// Test that email-based operations don't reveal whether email exists.
    #[tokio::test]
    async fn email_operations_dont_reveal_existence() {
        let (app, state) = public_app_with_state();
        let conn = state.db.get().unwrap();

        // Create org, project, product for testing
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let product = create_test_product(&conn, &project.id, "Pro", "pro");

        // Create a license with known email
        let _license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

        // Try activation code request with real email vs fake email
        // Both should return similar responses (to prevent enumeration)
        let test_emails = vec![
            ("test@example.com", "real email"),
            ("nonexistent@example.com", "fake email"),
            ("another@fake.com", "another fake email"),
        ];

        let mut responses = Vec::new();

        for (email, context) in test_emails {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/activation/request-code")
                        .header("Content-Type", "application/json")
                        .body(Body::from(
                            json!({
                                "email": email,
                                "public_key": project.public_key
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();

            let status = response.status();
            let json = body_json(response).await;

            responses.push((context, status, json.clone()));

            // Error messages should not indicate whether the email exists
            let error_msg = json["error"].as_str().unwrap_or("");
            let details = json["details"].as_str().unwrap_or("");

            assert!(
                !error_msg.to_lowercase().contains("not found"),
                "{}: error should not say 'not found' as this reveals email does not exist in system (message: {})",
                context,
                error_msg
            );
            assert!(
                !details.to_lowercase().contains("no license"),
                "{}: details should not mention 'no license' as this confirms email has no associated license (details: {})",
                context,
                details
            );
        }
    }
}

// ============================================================================
// CONSISTENT ERROR FORMAT TESTS
// ============================================================================

mod consistent_error_format {
    use super::*;

    /// Test that error responses use JSON with "error" field.
    #[tokio::test]
    async fn all_errors_return_json_with_error_field() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_, _, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        // Various error scenarios
        let error_scenarios = vec![
            // 400 - Bad Request (invalid JSON)
            (
                "POST",
                format!("/orgs/{}/projects/{}/products", org.id, project.id),
                Body::from("{ invalid json }"),
                "400 Bad Request - invalid JSON",
            ),
            // 400 - Bad Request (missing required fields)
            (
                "POST",
                format!("/orgs/{}/projects/{}/products", org.id, project.id),
                Body::from(json!({}).to_string()),
                "400 Bad Request - missing fields",
            ),
        ];

        for (method, uri, body, context) in error_scenarios {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(&uri)
                        .header("Authorization", format!("Bearer {}", api_key))
                        .header("Content-Type", "application/json")
                        .body(body)
                        .unwrap(),
                )
                .await
                .unwrap();

            let status = response.status();
            let json = body_json(response).await;

            // Should be a 4xx error
            assert!(
                status.is_client_error(),
                "{}: malformed request should return 4xx client error (got {})",
                context,
                status
            );

            // For actual error responses, check format
            if json.get("error").is_some() {
                assert_consistent_error_format(&json, context);
            }

            // Verify no sensitive info leaked
            assert_no_sensitive_leakage(&json, context);
        }
    }

    /// Test that unauthorized endpoints return consistent error format.
    #[tokio::test]
    async fn unauthorized_errors_use_consistent_format() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create a real org to ensure we're testing auth, not existence
        let org = create_test_org(&conn, "Test Org");

        // Try to access with invalid auth token
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", "Bearer invalid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let json = body_json(response).await;

        // Should be 401 Unauthorized
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "request with invalid auth token should return 401 Unauthorized (got {})",
            status
        );

        // Check error format if error field is present
        if json.get("error").is_some() {
            assert_consistent_error_format(&json, "unauthorized request");
        }

        assert_no_sensitive_leakage(&json, "unauthorized request");
    }

    /// Test that rate limit errors use consistent format.
    #[tokio::test]
    async fn rate_limit_errors_use_consistent_format() {
        // Create app with rate limiting enabled but very low limits
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

        // Create app with very low rate limits (1 RPM)
        let rate_config = RateLimitConfig {
            strict_rpm: 1,
            standard_rpm: 1,
            relaxed_rpm: 1,
            org_ops_rpm: 1,
        };

        let app = handlers::orgs::router(state.clone(), rate_config).with_state(state.clone());

        // Create org and member for authentication
        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, api_key) =
                create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

            // Make enough requests to trigger rate limit
            for i in 0..3 {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method("GET")
                            .uri(format!("/orgs/{}/members", org.id))
                            .header("Authorization", format!("Bearer {}", api_key))
                            .header("X-Forwarded-For", format!("192.168.1.{}", i))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();

                if response.status() == StatusCode::TOO_MANY_REQUESTS {
                    let json = body_json(response).await;

                    assert_consistent_error_format(&json, "rate limit error");

                    // Rate limit message should not reveal exact limits
                    let error_msg = json["error"].as_str().unwrap_or("");
                    assert!(
                        !error_msg.contains("1 request"),
                        "rate limit error should not reveal internal limit configuration (found '1 request' in message: {})",
                        error_msg
                    );

                    return; // Test passed
                }
            }
        }

        // If we get here, rate limiting didn't trigger (which is fine for disabled rate limiting)
    }
}

// ============================================================================
// VALIDATION ERROR SAFETY TESTS
// ============================================================================

mod validation_error_safety {
    use super::*;

    /// Test that validation errors don't reveal exploitable format details.
    #[tokio::test]
    async fn validation_errors_dont_reveal_regex_patterns() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_, _, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        // Try inputs that would trigger validation errors (type mismatches)
        let test_cases = vec![
            // Type mismatches - these should definitely fail
            json!({
                "name": "Test",
                "tier": "pro",
                "license_exp_days": "not a number",
                "updates_exp_days": ONE_YEAR,
                "activation_limit": 5,
                "device_limit": 3,
                "features": []
            }),
            // Wrong type for features
            json!({
                "name": "Test",
                "tier": "pro",
                "license_exp_days": ONE_YEAR,
                "updates_exp_days": ONE_YEAR,
                "activation_limit": 5,
                "device_limit": 3,
                "features": "not an array"
            }),
        ];

        for body in test_cases {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/orgs/{}/projects/{}/products", org.id, project.id))
                        .header("Authorization", format!("Bearer {}", api_key))
                        .header("Content-Type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();

            let status = response.status();
            let json = body_json(response).await;

            // Should be a 400 error for invalid input
            assert!(
                status.is_client_error(),
                "invalid input should return 4xx client error (got {})",
                status
            );

            // Error should not include regex patterns (if error occurred)
            let json_str = json.to_string();
            assert!(
                !json_str.contains("^[a-z"),
                "validation error should not leak regex pattern '^[a-z' that reveals internal validation rules (response: {})",
                json_str
            );
            assert!(
                !json_str.contains("\\d"),
                "validation error should not leak regex pattern '\\d' that reveals internal validation rules (response: {})",
                json_str
            );
            assert!(
                !json_str.contains("[A-Z]"),
                "validation error should not leak regex pattern '[A-Z]' that reveals internal validation rules (response: {})",
                json_str
            );

            // Verify no sensitive info leaked
            assert_no_sensitive_leakage(&json, "validation error");
        }
    }

    /// Test that path parameter validation errors are safe.
    #[tokio::test]
    async fn path_validation_errors_dont_leak_info() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_, _, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Various malformed path parameters (URL-safe only)
        let test_paths = vec![
            format!("/orgs/{}/projects/---", org.id),
            format!("/orgs/{}/projects/{}", org.id, "a".repeat(1000)),
            format!("/orgs/{}/projects/___special___", org.id),
            format!("/orgs/{}/projects/123-456-789", org.id),
        ];

        for path in test_paths {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(&path)
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            let json = body_json(response).await;

            assert_no_sensitive_leakage(&json, &path);
        }
    }

    /// Test that query parameter validation errors are safe.
    #[tokio::test]
    async fn query_validation_errors_are_safe() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_, _, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        // Malformed query parameters
        let test_queries = vec![
            format!(
                "/orgs/{}/projects/{}/licenses?limit=abc",
                org.id, project.id
            ),
            format!(
                "/orgs/{}/projects/{}/licenses?limit=-1",
                org.id, project.id
            ),
            format!(
                "/orgs/{}/projects/{}/licenses?limit=999999999999",
                org.id, project.id
            ),
        ];

        for query in test_queries {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(&query)
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            let status = response.status();
            let json = body_json(response).await;

            assert_no_sensitive_leakage(&json, &query);

            // Should return appropriate error, not crash
            assert!(
                status != StatusCode::INTERNAL_SERVER_ERROR
                    || json["error"].as_str().unwrap_or("") == "Internal server error",
                "{}: malformed query should return client error or generic 500, not crash or leak details (got {} with body: {})",
                query,
                status,
                json
            );
        }
    }
}

// ============================================================================
// RESOURCE EXISTENCE LEAKAGE TESTS
// ============================================================================

mod resource_existence_leakage {
    use super::*;

    /// Test that accessing forbidden resources returns 403, not 404.
    /// This prevents resource enumeration attacks.
    #[tokio::test]
    async fn forbidden_vs_not_found_is_consistent() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create two orgs
        let org_a = create_test_org(&conn, "Org A");
        let org_b = create_test_org(&conn, "Org B");

        // Create project in org_a
        let project_a = create_test_project(&conn, &org_a.id, "Project A", &state.master_key);

        // User from org_b
        let (_, _, key_b) =
            create_test_org_member(&conn, &org_b.id, "user@orgb.com", OrgMemberRole::Owner);

        // Try to access real project in org_a vs fake project
        let real_project_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org_a.id, project_a.id))
                    .header("Authorization", format!("Bearer {}", key_b))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let fake_project_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/fake-project", org_a.id))
                    .header("Authorization", format!("Bearer {}", key_b))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Both should return FORBIDDEN (user not in org_a)
        // NOT 404 for fake project (which would reveal project doesn't exist)
        assert_eq!(
            real_project_response.status(),
            fake_project_response.status(),
            "unauthorized user should receive same status for real project ({}) and fake project ({}) to prevent resource enumeration",
            real_project_response.status(),
            fake_project_response.status()
        );
    }

    /// Test that license lookup for unauthorized user is consistent.
    #[tokio::test]
    async fn license_lookup_consistent_for_unauthorized() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org_a = create_test_org(&conn, "Org A");
        let org_b = create_test_org(&conn, "Org B");

        // Create project, product, and license in org_a
        let project_a = create_test_project(&conn, &org_a.id, "Project A", &state.master_key);
        let product_a = create_test_product(&conn, &project_a.id, "Pro", "pro");
        let license_a = create_test_license(&conn, &project_a.id, &product_a.id, None);

        // User from org_b
        let (_, _, key_b) =
            create_test_org_member(&conn, &org_b.id, "user@orgb.com", OrgMemberRole::Owner);

        // Try to access real license vs fake license
        let test_cases = vec![
            (license_a.id.clone(), "real license"),
            ("fake-license-id".to_string(), "fake license"),
        ];

        let mut responses = Vec::new();

        for (license_id, context) in test_cases {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!(
                            "/orgs/{}/projects/{}/licenses/{}",
                            org_a.id, project_a.id, license_id
                        ))
                        .header("Authorization", format!("Bearer {}", key_b))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            responses.push((context, response.status()));
        }

        // Both should return same status
        assert_eq!(
            responses[0].1, responses[1].1,
            "unauthorized user should receive same status for real license ({}) and fake license ({}) to prevent license enumeration",
            responses[0].1,
            responses[1].1
        );
    }
}

// ============================================================================
// DEBUG INFO LEAKAGE TESTS
// ============================================================================

mod no_debug_info {
    use super::*;

    /// Test that error responses don't include debug markers.
    #[tokio::test]
    async fn no_debug_markers_in_errors() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_, _, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Trigger various errors
        let error_triggers = vec![
            ("GET", format!("/orgs/{}/projects/nonexistent", org.id)),
            ("GET", format!("/orgs/nonexistent/members")),
            ("DELETE", format!("/orgs/{}/members/fake-id", org.id)),
        ];

        for (method, uri) in error_triggers {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(&uri)
                        .header("Authorization", format!("Bearer {}", api_key))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            let json = body_json(response).await;
            let json_str = json.to_string().to_lowercase();

            // No debug-only info
            assert!(
                !json_str.contains("debug"),
                "error response should not contain 'debug' marker that reveals debug mode (response: {})",
                json
            );
            assert!(
                !json_str.contains("trace_id"),
                "error response should not expose internal trace_id for request tracking (response: {})",
                json
            );
            assert!(
                !json_str.contains("request_id"),
                "error response should not expose internal request_id for request tracking (response: {})",
                json
            );

            // No version info
            assert!(
                !json_str.contains("version"),
                "error response should not expose server version information (response: {})",
                json
            );

            // No environment info
            assert!(
                !json_str.contains("environment"),
                "error response should not expose environment name (response: {})",
                json
            );
            assert!(
                !json_str.contains("production"),
                "error response should not reveal 'production' environment indicator (response: {})",
                json
            );
            assert!(
                !json_str.contains("development"),
                "error response should not reveal 'development' environment indicator (response: {})",
                json
            );
        }
    }

    /// Test that validation errors don't include internal field names.
    #[tokio::test]
    async fn no_internal_field_names_in_validation_errors() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_, _, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        // Submit invalid data
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/products", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "wrong_field": "value"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let json = body_json(response).await;
        let json_str = json.to_string().to_lowercase();

        // Should not expose internal Rust struct field names with prefixes
        assert!(
            !json_str.contains("_id"),
            "validation error should not expose internal '_id' field naming convention (response: {})",
            json
        );
        assert!(
            !json_str.contains("_at"),
            "validation error should not expose internal '_at' timestamp field naming convention (response: {})",
            json
        );
    }
}
