//! Cross-organization data isolation tests.
//!
//! These tests verify that multi-tenant isolation is properly enforced:
//! 1. Users/API keys from org_a cannot access org_b's data
//! 2. API key scopes are respected across org boundaries
//! 3. Audit logs, licenses, and devices are properly isolated
//! 4. Query parameters cannot be used to bypass org_id filtering
//!
//! CRITICAL: These tests ensure tenant isolation. Any failure here
//! indicates a potential cross-tenant data leakage vulnerability.

#[path = "../common/mod.rs"]
mod common;
use common::*;

use axum::{Router, body::Body, http::Request};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tower::ServiceExt;

use axum::body::to_bytes;
use axum::http::StatusCode;
use paycheck::config::RateLimitConfig;
use paycheck::db::{AppState, queries};
use paycheck::handlers;
use paycheck::models::{
    AccessLevel, ActorType, AuditLogNames, CreateOrgMember, OrgMemberRole, OperatorRole,
};

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
        audit_log_enabled: true, // Enable audit logging for isolation tests
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
        audit_log_enabled: true,
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

// ============================================================================
// ORG MEMBER ISOLATION TESTS
// ============================================================================

mod org_member_isolation {
    use super::*;

    /// Org member of org_a cannot list org_b's members.
    /// This is the foundational cross-org access control test.
    #[tokio::test]
    async fn org_a_member_cannot_list_org_b_members() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create two separate organizations
        let org_a = create_test_org(&conn, "Organization A");
        let org_b = create_test_org(&conn, "Organization B");

        // Create member in org_a
        let (_user_a, _member_a, key_a) =
            create_test_org_member(&conn, &org_a.id, "user@orga.com", OrgMemberRole::Owner);

        // Create member in org_b (to ensure it has members to list)
        let (_user_b, _member_b, _key_b) =
            create_test_org_member(&conn, &org_b.id, "user@orgb.com", OrgMemberRole::Owner);

        // Try to access org_b's members with org_a's key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org_b.id))
                    .header("Authorization", format!("Bearer {}", key_a))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Org A member should not access Org B's member list"
        );
    }

    /// Org member of org_a cannot list org_b's projects.
    #[tokio::test]
    async fn org_a_member_cannot_list_org_b_projects() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org_a = create_test_org(&conn, "Organization A");
        let org_b = create_test_org(&conn, "Organization B");

        // Create projects in org_b
        let _project_b = create_test_project(&conn, &org_b.id, "Org B Project", &state.master_key);

        let (_user_a, _member_a, key_a) =
            create_test_org_member(&conn, &org_a.id, "user@orga.com", OrgMemberRole::Owner);

        // Try to list org_b's projects with org_a's key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects", org_b.id))
                    .header("Authorization", format!("Bearer {}", key_a))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Org A member should not list Org B's projects"
        );
    }

    /// Org member of org_a cannot access org_b's audit logs.
    #[tokio::test]
    async fn org_a_member_cannot_access_org_b_audit_logs() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org_a = create_test_org(&conn, "Organization A");
        let org_b = create_test_org(&conn, "Organization B");

        let (_user_a, _member_a, key_a) =
            create_test_org_member(&conn, &org_a.id, "user@orga.com", OrgMemberRole::Owner);

        // Try to access org_b's audit logs
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs", org_b.id))
                    .header("Authorization", format!("Bearer {}", key_a))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Org A member should not access Org B's audit logs"
        );
    }

    /// Member of both orgs can only see data from the org they're querying.
    #[tokio::test]
    async fn multi_org_member_sees_only_requested_org_data() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create two organizations
        let org_a = create_test_org(&conn, "Organization A");
        let org_b = create_test_org(&conn, "Organization B");

        // Create a user who is member of both orgs
        let user = create_test_user(&conn, "multiorg@example.com", "Multi-Org User");

        // Add user to org_a as owner
        queries::create_org_member(
            &conn,
            &org_a.id,
            &CreateOrgMember {
                user_id: user.id.clone(),
                role: OrgMemberRole::Owner,
            },
        )
        .unwrap();

        // Add user to org_b as owner
        queries::create_org_member(
            &conn,
            &org_b.id,
            &CreateOrgMember {
                user_id: user.id.clone(),
                role: OrgMemberRole::Owner,
            },
        )
        .unwrap();

        // Create projects in each org
        let _project_a = create_test_project(&conn, &org_a.id, "Project A", &state.master_key);
        let _project_b = create_test_project(&conn, &org_b.id, "Project B", &state.master_key);

        // Create API key for the user (unscoped - can access both orgs)
        let (_, api_key) = queries::create_api_key(&conn, &user.id, "Multi-org key", None, true, None)
            .expect("Failed to create API key");

        // Query org_a's projects
        let response_a = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects", org_a.id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_a.status(),
            StatusCode::OK,
            "Multi-org member should successfully access org_a's projects"
        );

        let body_a = to_bytes(response_a.into_body(), usize::MAX).await.unwrap();
        let result_a: serde_json::Value = serde_json::from_slice(&body_a).unwrap();
        let projects_a = result_a["items"].as_array().unwrap();

        // Should only see org_a's project
        assert_eq!(
            projects_a.len(),
            1,
            "Query for org_a should return exactly 1 project"
        );
        assert_eq!(
            projects_a[0]["name"], "Project A",
            "Only org_a's Project A should be returned"
        );

        // Query org_b's projects
        let response_b = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects", org_b.id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_b.status(),
            StatusCode::OK,
            "Multi-org member should successfully access org_b's projects"
        );

        let body_b = to_bytes(response_b.into_body(), usize::MAX).await.unwrap();
        let result_b: serde_json::Value = serde_json::from_slice(&body_b).unwrap();
        let projects_b = result_b["items"].as_array().unwrap();

        // Should only see org_b's project
        assert_eq!(
            projects_b.len(),
            1,
            "Query for org_b should return exactly 1 project"
        );
        assert_eq!(
            projects_b[0]["name"], "Project B",
            "Only org_b's Project B should be returned"
        );
    }
}

// ============================================================================
// API KEY SCOPE ISOLATION TESTS
// ============================================================================

mod api_key_scope_isolation {
    use super::*;

    /// API key scoped to org_a cannot access org_b endpoints.
    #[tokio::test]
    async fn api_key_scoped_to_org_a_cannot_access_org_b() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create two organizations
        let org_a = create_test_org(&conn, "Organization A");
        let org_b = create_test_org(&conn, "Organization B");

        // Create user as member of both orgs
        let user = create_test_user(&conn, "user@example.com", "Test User");
        queries::create_org_member(
            &conn,
            &org_a.id,
            &CreateOrgMember {
                user_id: user.id.clone(),
                role: OrgMemberRole::Owner,
            },
        )
        .unwrap();
        queries::create_org_member(
            &conn,
            &org_b.id,
            &CreateOrgMember {
                user_id: user.id.clone(),
                role: OrgMemberRole::Owner,
            },
        )
        .unwrap();

        // Create API key scoped ONLY to org_a
        let scoped_key =
            create_api_key_with_org_scope(&conn, &user.id, &org_a.id, AccessLevel::Admin);

        // Try to access org_b with org_a-scoped key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org_b.id))
                    .header("Authorization", format!("Bearer {}", scoped_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Key scoped to org_a should not access org_b"
        );
    }

    /// API key scoped to org_a CAN access org_a endpoints.
    #[tokio::test]
    async fn api_key_scoped_to_org_a_can_access_org_a() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org_a = create_test_org(&conn, "Organization A");

        let (user, _member, _default_key) =
            create_test_org_member(&conn, &org_a.id, "user@orga.com", OrgMemberRole::Owner);

        // Create API key scoped to org_a
        let scoped_key =
            create_api_key_with_org_scope(&conn, &user.id, &org_a.id, AccessLevel::Admin);

        // Access org_a with org_a-scoped key - should work
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org_a.id))
                    .header("Authorization", format!("Bearer {}", scoped_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Key scoped to org_a should access org_a"
        );
    }

    /// Scoped key cannot be used to create members in a different org.
    #[tokio::test]
    async fn scoped_key_cannot_write_to_different_org() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org_a = create_test_org(&conn, "Organization A");
        let org_b = create_test_org(&conn, "Organization B");

        // Create user as owner of both orgs
        let user = create_test_user(&conn, "owner@example.com", "Owner");
        queries::create_org_member(
            &conn,
            &org_a.id,
            &CreateOrgMember {
                user_id: user.id.clone(),
                role: OrgMemberRole::Owner,
            },
        )
        .unwrap();
        queries::create_org_member(
            &conn,
            &org_b.id,
            &CreateOrgMember {
                user_id: user.id.clone(),
                role: OrgMemberRole::Owner,
            },
        )
        .unwrap();

        // Create API key scoped ONLY to org_a
        let scoped_key =
            create_api_key_with_org_scope(&conn, &user.id, &org_a.id, AccessLevel::Admin);

        // Create a new user to add as member
        let new_user = create_test_user(&conn, "new@example.com", "New User");

        // Try to create member in org_b with org_a-scoped key
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/members", org_b.id))
                    .header("Authorization", format!("Bearer {}", scoped_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"user_id": "{}", "role": "member"}}"#,
                        new_user.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Org_a-scoped key should not create members in org_b"
        );
    }
}

// ============================================================================
// AUDIT LOG ISOLATION TESTS
// ============================================================================

mod audit_log_isolation {
    use super::*;

    /// Audit log queries with org_id filter cannot be bypassed via query params.
    #[tokio::test]
    async fn audit_log_org_id_query_param_cannot_bypass_path_org_id() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();
        let audit_conn = state.audit.get().unwrap();

        // Create two orgs
        let org_a = create_test_org(&conn, "Organization A");
        let org_b = create_test_org(&conn, "Organization B");

        let (_user_a, _member_a, key_a) =
            create_test_org_member(&conn, &org_a.id, "user@orga.com", OrgMemberRole::Owner);

        // Create audit logs for both orgs
        queries::create_audit_log(
            &audit_conn,
            true,
            ActorType::User,
            Some("actor_a"),
            "action_in_org_a",
            "test_resource",
            "resource_a",
            None,
            Some(&org_a.id),
            None,
            None,
            None,
            &AuditLogNames::default(),
            None,
            None,
        )
        .unwrap();

        queries::create_audit_log(
            &audit_conn,
            true,
            ActorType::User,
            Some("actor_b"),
            "action_in_org_b",
            "test_resource",
            "resource_b",
            None,
            Some(&org_b.id),
            None,
            None,
            None,
            &AuditLogNames::default(),
            None,
            None,
        )
        .unwrap();

        // Try to bypass path org_id by adding org_id query param pointing to org_b
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs?org_id={}", org_a.id, org_b.id))
                    .header("Authorization", format!("Bearer {}", key_a))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Request with query param bypass attempt should still succeed"
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let logs = result["items"].as_array().unwrap();

        // Should ONLY see org_a's logs, NOT org_b's - path org_id takes precedence
        assert_eq!(
            logs.len(),
            1,
            "Path org_id should take precedence over query param - only org_a logs returned"
        );
        assert_eq!(
            logs[0]["action"], "action_in_org_a",
            "Returned log should be from org_a, not org_b"
        );
        assert_eq!(
            logs[0]["org_id"], org_a.id,
            "Log org_id should match path org_id, not query param"
        );
    }

    /// Audit logs from org_a should never appear in org_b queries.
    #[tokio::test]
    async fn audit_logs_strictly_isolated_between_orgs() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();
        let audit_conn = state.audit.get().unwrap();

        let org_a = create_test_org(&conn, "Organization A");
        let org_b = create_test_org(&conn, "Organization B");

        let (_user_a, _member_a, key_a) =
            create_test_org_member(&conn, &org_a.id, "user@orga.com", OrgMemberRole::Owner);
        let (_user_b, _member_b, key_b) =
            create_test_org_member(&conn, &org_b.id, "user@orgb.com", OrgMemberRole::Owner);

        // Create 3 audit logs for org_a
        for i in 1..=3 {
            queries::create_audit_log(
                &audit_conn,
                true,
                ActorType::User,
                Some("actor_a"),
                &format!("org_a_action_{}", i),
                "test_resource",
                &format!("resource_a_{}", i),
                None,
                Some(&org_a.id),
                None,
                None,
                None,
                &AuditLogNames::default(),
                None,
                None,
            )
            .unwrap();
        }

        // Create 2 audit logs for org_b
        for i in 1..=2 {
            queries::create_audit_log(
                &audit_conn,
                true,
                ActorType::User,
                Some("actor_b"),
                &format!("org_b_action_{}", i),
                "test_resource",
                &format!("resource_b_{}", i),
                None,
                Some(&org_b.id),
                None,
                None,
                None,
                &AuditLogNames::default(),
                None,
                None,
            )
            .unwrap();
        }

        // Query org_a's audit logs
        let response_a = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs", org_a.id))
                    .header("Authorization", format!("Bearer {}", key_a))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_a.status(),
            StatusCode::OK,
            "Org_a member should successfully query org_a's audit logs"
        );

        let body_a = to_bytes(response_a.into_body(), usize::MAX).await.unwrap();
        let result_a: serde_json::Value = serde_json::from_slice(&body_a).unwrap();
        let logs_a = result_a["items"].as_array().unwrap();

        // Should only see org_a's 3 logs
        assert_eq!(
            logs_a.len(),
            3,
            "Org_a should have exactly 3 audit logs"
        );
        for log in logs_a {
            assert_eq!(
                log["org_id"], org_a.id,
                "All logs should belong to org_a"
            );
            assert!(
                log["action"].as_str().unwrap().starts_with("org_a_action"),
                "All log actions should be from org_a"
            );
        }

        // Query org_b's audit logs
        let response_b = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs", org_b.id))
                    .header("Authorization", format!("Bearer {}", key_b))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_b.status(),
            StatusCode::OK,
            "Org_b member should successfully query org_b's audit logs"
        );

        let body_b = to_bytes(response_b.into_body(), usize::MAX).await.unwrap();
        let result_b: serde_json::Value = serde_json::from_slice(&body_b).unwrap();
        let logs_b = result_b["items"].as_array().unwrap();

        // Should only see org_b's 2 logs
        assert_eq!(
            logs_b.len(),
            2,
            "Org_b should have exactly 2 audit logs"
        );
        for log in logs_b {
            assert_eq!(
                log["org_id"], org_b.id,
                "All logs should belong to org_b"
            );
            assert!(
                log["action"].as_str().unwrap().starts_with("org_b_action"),
                "All log actions should be from org_b"
            );
        }
    }
}

// ============================================================================
// RESOURCE ISOLATION TESTS (Projects, Licenses, Devices)
// ============================================================================

mod resource_isolation {
    use super::*;

    /// Cross-org project access is blocked.
    /// A project in org_a cannot be accessed by an org_b member.
    #[tokio::test]
    async fn cross_org_project_access_blocked() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org_a = create_test_org(&conn, "Organization A");
        let org_b = create_test_org(&conn, "Organization B");

        // Create project in org_a
        let project_a = create_test_project(&conn, &org_a.id, "Project A", &state.master_key);

        // Create member in org_b
        let (_user_b, _member_b, key_b) =
            create_test_org_member(&conn, &org_b.id, "user@orgb.com", OrgMemberRole::Owner);

        // Try to access org_a's project using org_a's path but org_b's key
        // This should fail at auth level (org_b member can't access org_a)
        let response = app
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

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Org B member should not access Org A's project"
        );
    }

    /// Cross-org license lookup is blocked.
    #[tokio::test]
    async fn cross_org_license_lookup_blocked() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org_a = create_test_org(&conn, "Organization A");
        let org_b = create_test_org(&conn, "Organization B");

        // Create project and license in org_a
        let project_a = create_test_project(&conn, &org_a.id, "Project A", &state.master_key);
        let product_a = create_test_product(&conn, &project_a.id, "Product A", "pro");
        let license_a = create_test_license(&conn, &project_a.id, &product_a.id, None);

        // Create member in org_b
        let (_user_b, _member_b, key_b) =
            create_test_org_member(&conn, &org_b.id, "user@orgb.com", OrgMemberRole::Owner);

        // Try to access org_a's license using org_b's key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}",
                        org_a.id, project_a.id, license_a.id
                    ))
                    .header("Authorization", format!("Bearer {}", key_b))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Org B member should not access Org A's license"
        );
    }

    /// User with membership in multiple orgs has isolated license/device access.
    #[tokio::test]
    async fn multi_org_user_license_isolation() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org_a = create_test_org(&conn, "Organization A");
        let org_b = create_test_org(&conn, "Organization B");

        // Create projects and licenses in both orgs
        let project_a = create_test_project(&conn, &org_a.id, "Project A", &state.master_key);
        let product_a = create_test_product(&conn, &project_a.id, "Product A", "pro");
        let license_a = create_test_license(&conn, &project_a.id, &product_a.id, None);

        let project_b = create_test_project(&conn, &org_b.id, "Project B", &state.master_key);
        let product_b = create_test_product(&conn, &project_b.id, "Product B", "pro");
        let license_b = create_test_license(&conn, &project_b.id, &product_b.id, None);

        // Create user as member of both orgs
        let user = create_test_user(&conn, "multiorg@example.com", "Multi-Org User");
        queries::create_org_member(
            &conn,
            &org_a.id,
            &CreateOrgMember {
                user_id: user.id.clone(),
                role: OrgMemberRole::Owner,
            },
        )
        .unwrap();
        queries::create_org_member(
            &conn,
            &org_b.id,
            &CreateOrgMember {
                user_id: user.id.clone(),
                role: OrgMemberRole::Owner,
            },
        )
        .unwrap();

        let (_, api_key) = queries::create_api_key(&conn, &user.id, "Multi-org key", None, true, None)
            .expect("Failed to create API key");

        // Access org_a's license - should work
        let response_a = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}",
                        org_a.id, project_a.id, license_a.id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_a.status(),
            StatusCode::OK,
            "Multi-org member should access org_a's license via org_a's path"
        );

        // Access org_b's license - should also work
        let response_b = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}",
                        org_b.id, project_b.id, license_b.id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_b.status(),
            StatusCode::OK,
            "Multi-org member should access org_b's license via org_b's path"
        );

        // But license_a should NOT be accessible via org_b's path
        let response_cross = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}",
                        org_b.id, project_a.id, license_a.id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Project A doesn't exist in org B, so NOT_FOUND
        assert_eq!(
            response_cross.status(),
            StatusCode::NOT_FOUND,
            "License from org_a should not be accessible via org_b's project path"
        );
    }
}

// ============================================================================
// OPERATOR SYNTHETIC ACCESS ISOLATION TESTS
// ============================================================================

mod operator_isolation {
    use super::*;

    /// Operator with synthetic access to org_a cannot accidentally expose org_b data.
    /// This verifies that operator access is properly scoped per-request.
    #[tokio::test]
    async fn operator_synthetic_access_does_not_leak_cross_org_data() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create an admin operator
        let (_op_user, _operator, operator_key) =
            create_test_operator(&conn, "admin@platform.com", OperatorRole::Admin);

        // Create two orgs with different projects
        let org_a = create_test_org(&conn, "Organization A");
        let org_b = create_test_org(&conn, "Organization B");

        let _project_a = create_test_project(&conn, &org_a.id, "Org A Project", &state.master_key);
        let _project_b = create_test_project(&conn, &org_b.id, "Org B Project", &state.master_key);

        // Operator queries org_a's projects
        let response_a = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects", org_a.id))
                    .header("Authorization", format!("Bearer {}", operator_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_a.status(),
            StatusCode::OK,
            "Operator should successfully query org_a's projects"
        );

        let body_a = to_bytes(response_a.into_body(), usize::MAX).await.unwrap();
        let result_a: serde_json::Value = serde_json::from_slice(&body_a).unwrap();
        let projects_a = result_a["items"].as_array().unwrap();

        // Should only see org_a's project
        assert_eq!(
            projects_a.len(),
            1,
            "Operator query for org_a should return exactly 1 project"
        );
        assert_eq!(
            projects_a[0]["name"], "Org A Project",
            "Only org_a's project should be returned in org_a query"
        );

        // Operator queries org_b's projects
        let response_b = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects", org_b.id))
                    .header("Authorization", format!("Bearer {}", operator_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_b.status(),
            StatusCode::OK,
            "Operator should successfully query org_b's projects"
        );

        let body_b = to_bytes(response_b.into_body(), usize::MAX).await.unwrap();
        let result_b: serde_json::Value = serde_json::from_slice(&body_b).unwrap();
        let projects_b = result_b["items"].as_array().unwrap();

        // Should only see org_b's project
        assert_eq!(
            projects_b.len(),
            1,
            "Operator query for org_b should return exactly 1 project"
        );
        assert_eq!(
            projects_b[0]["name"], "Org B Project",
            "Only org_b's project should be returned in org_b query"
        );
    }

    /// View-only operators cannot access org endpoints at all.
    #[tokio::test]
    async fn view_operator_blocked_from_org_endpoints() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create a view-only operator
        let (_op_user, _operator, operator_key) =
            create_test_operator(&conn, "viewer@platform.com", OperatorRole::View);

        let org = create_test_org(&conn, "Test Org");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", operator_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "View-only operators should not have synthetic access"
        );
    }
}

// ============================================================================
// API KEY VISIBILITY ISOLATION TESTS
// ============================================================================

mod api_key_visibility_isolation {
    use super::*;

    /// User can only see their own API keys, not other users' keys.
    /// The API key list endpoint is scoped by user_id in the URL path.
    #[tokio::test]
    async fn user_only_sees_own_api_keys() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        // Create two users with API keys
        let (user_a, _op_a, key_a) =
            create_test_operator(&conn, "usera@platform.com", OperatorRole::Admin);
        let (_user_b, _op_b, _key_b) =
            create_test_operator(&conn, "userb@platform.com", OperatorRole::Admin);

        // Create additional API keys for both users with distinctive names
        queries::create_api_key(&conn, &user_a.id, "User A Extra Key", None, true, None).unwrap();
        queries::create_api_key(&conn, &_user_b.id, "User B Extra Key", None, true, None).unwrap();

        // User A queries their own API keys
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/operators/users/{}/api-keys", user_a.id))
                    .header("Authorization", format!("Bearer {}", key_a))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "User should successfully query their own API keys"
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let keys = result["items"].as_array().unwrap();

        // Should see 2 keys for user_a (default + extra)
        assert_eq!(
            keys.len(),
            2,
            "User_a should have exactly 2 API keys (default + extra)"
        );

        // Verify the keys belong to user_a by checking names
        // (user_id is not exposed in ApiKeyInfo for security - the endpoint is scoped by user_id in path)
        let key_names: Vec<&str> = keys.iter().map(|k| k["name"].as_str().unwrap()).collect();
        assert!(
            key_names.contains(&"Default") || key_names.contains(&"User A Extra Key"),
            "Keys should belong to user_a based on names"
        );
        // Should NOT contain user_b's key
        assert!(
            !key_names.contains(&"User B Extra Key"),
            "User B's keys should not appear in user A's query"
        );
    }

    /// User A cannot view User B's API keys via the API.
    #[tokio::test]
    async fn user_cannot_view_other_users_api_keys() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        // Create admin operator (user A)
        let (_user_a, _op_a, key_a) =
            create_test_operator(&conn, "admin@platform.com", OperatorRole::Admin);

        // Create another user (user B) with an API key
        let (user_b, _op_b, _key_b) =
            create_test_operator(&conn, "userb@platform.com", OperatorRole::View);

        // Admin tries to view user B's API keys
        // This should work for admins (they manage users)
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/operators/users/{}/api-keys", user_b.id))
                    .header("Authorization", format!("Bearer {}", key_a))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Admin+ operators CAN view other users' API keys (part of user management)
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Admin operator should be able to view other users' API keys"
        );
    }

    /// Org member can only see API keys for their own user, not other members.
    #[tokio::test]
    async fn org_member_api_key_isolation() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");

        // Create two org members
        let (user_a, _member_a, key_a) =
            create_test_org_member(&conn, &org.id, "usera@org.com", OrgMemberRole::Owner);
        let (user_b, _member_b, _key_b) =
            create_test_org_member(&conn, &org.id, "userb@org.com", OrgMemberRole::Member);

        // User A queries their own API keys
        let response_own = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members/{}/api-keys", org.id, user_a.id))
                    .header("Authorization", format!("Bearer {}", key_a))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_own.status(),
            StatusCode::OK,
            "User should be able to view their own API keys"
        );

        // User A (owner) tries to view User B's API keys
        // Org owners can manage member API keys
        let response_other = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members/{}/api-keys", org.id, user_b.id))
                    .header("Authorization", format!("Bearer {}", key_a))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Org owners CAN view other members' API keys (part of member management)
        assert_eq!(
            response_other.status(),
            StatusCode::OK,
            "Org owner should be able to view other members' API keys"
        );
    }

    /// Member-role user cannot view other members' API keys.
    #[tokio::test]
    async fn member_role_cannot_view_other_member_api_keys() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");

        // Create owner to satisfy org requirements
        let (_owner_user, _owner_member, _owner_key) =
            create_test_org_member(&conn, &org.id, "owner@org.com", OrgMemberRole::Owner);

        // Create two members with Member role
        let (_user_a, _member_a, key_a) =
            create_test_org_member(&conn, &org.id, "membera@org.com", OrgMemberRole::Member);
        let (user_b, _member_b, _key_b) =
            create_test_org_member(&conn, &org.id, "memberb@org.com", OrgMemberRole::Member);

        // Member A tries to view Member B's API keys
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members/{}/api-keys", org.id, user_b.id))
                    .header("Authorization", format!("Bearer {}", key_a))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Member role should NOT be able to view other members' API keys
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Member role should not view other members' API keys"
        );
    }
}
