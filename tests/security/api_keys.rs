//! Security tests for API key authentication and scope enforcement.
//!
//! These tests verify that:
//! 1. Expired and revoked API keys are rejected with 401 Unauthorized
//! 2. API key scopes properly restrict access to orgs and projects
//! 3. Read-only scopes block write operations
//! 4. Deleted users and org members cannot authenticate
//!
//! CRITICAL: These tests ensure security boundaries are enforced correctly.
//! Any failure here indicates a potential authorization bypass vulnerability.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[path = "../common/mod.rs"]
mod common;
use common::*;

use paycheck::config::RateLimitConfig;
use paycheck::db::{AppState, queries};
use paycheck::handlers;
use paycheck::models::{AccessLevel, OrgMemberRole};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

// ============================================================================
// Test App Setup Helper
// ============================================================================

/// Creates a test app with the full org router (with middleware).
/// This is the standard setup for testing org API authorization.
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

// ============================================================================
// EXPIRED AND REVOKED API KEYS
// ============================================================================

mod expired_and_revoked_keys {
    use super::*;

    /// Verify that an expired API key returns 401 Unauthorized.
    /// This is critical - expired keys must not grant any access.
    #[tokio::test]
    async fn test_expired_api_key_returns_401() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create org and member
        let org = create_test_org(&conn, "Test Org");
        let (user, _member, _valid_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Create an expired API key for the same user
        let expired_key = create_expired_api_key(&conn, &user.id);

        // Try to access org endpoint with expired key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", expired_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Expired API key should return 401 Unauthorized"
        );
    }

    /// Verify that a revoked API key returns 401 Unauthorized.
    /// This is critical - revoked keys must be immediately invalidated.
    #[tokio::test]
    async fn test_revoked_api_key_returns_401() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create org and member
        let org = create_test_org(&conn, "Test Org");
        let (user, _member, _valid_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Create a revoked API key for the same user
        let revoked_key = create_revoked_api_key(&conn, &user.id);

        // Try to access org endpoint with revoked key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", revoked_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Revoked API key should return 401 Unauthorized"
        );
    }
}

// ============================================================================
// API KEY SCOPE ENFORCEMENT (CRITICAL SECURITY TESTS)
// ============================================================================

mod scope_enforcement {
    use super::*;

    /// Verify that a key scoped to org_a cannot access org_b.
    /// This prevents cross-tenant data access.
    #[tokio::test]
    async fn test_scoped_key_cannot_access_different_org() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create two organizations
        let org_a = create_test_org(&conn, "Org A");
        let org_b = create_test_org(&conn, "Org B");

        // Create user as member of both orgs
        let user = create_test_user(&conn, "user@test.com", "Test User");
        queries::create_org_member(
            &conn,
            &org_a.id,
            &paycheck::models::CreateOrgMember {
                user_id: user.id.clone(),
                role: OrgMemberRole::Owner,
            },
        )
        .unwrap();
        queries::create_org_member(
            &conn,
            &org_b.id,
            &paycheck::models::CreateOrgMember {
                user_id: user.id.clone(),
                role: OrgMemberRole::Owner,
            },
        )
        .unwrap();

        // Create API key scoped to org_a only
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

    /// Verify that a key scoped to project_a cannot access project_b in the same org.
    /// This provides project-level isolation within an organization.
    #[tokio::test]
    async fn test_scoped_key_cannot_access_different_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create org with two projects
        let org = create_test_org(&conn, "Test Org");
        let project_a = create_test_project(&conn, &org.id, "Project A", &state.master_key);
        let project_b = create_test_project(&conn, &org.id, "Project B", &state.master_key);

        // Create user as org owner
        let (user, _member, _unscoped_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Create API key scoped to project_a only
        let scoped_key = create_api_key_with_project_scope(
            &conn,
            &user.id,
            &org.id,
            &project_a.id,
            AccessLevel::Admin,
        );

        // Try to access project_b with project_a-scoped key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project_b.id))
                    .header("Authorization", format!("Bearer {}", scoped_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            response.status() == StatusCode::FORBIDDEN
                || response.status() == StatusCode::NOT_FOUND,
            "Key scoped to project_a should not access project_b, got: {}",
            response.status()
        );
    }

    /// Verify that a key with org scope can access all projects in that org.
    /// Org-level scope should provide access to all child resources.
    #[tokio::test]
    async fn test_org_scoped_key_can_access_all_projects_in_org() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create org with multiple projects
        let org = create_test_org(&conn, "Test Org");
        let project_a = create_test_project(&conn, &org.id, "Project A", &state.master_key);
        let project_b = create_test_project(&conn, &org.id, "Project B", &state.master_key);

        // Create user as org owner
        let (user, _member, _unscoped_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Create API key with org-level scope
        let org_scoped_key =
            create_api_key_with_org_scope(&conn, &user.id, &org.id, AccessLevel::Admin);

        // Access both projects with org-scoped key
        let app_clone = app.clone();
        let response_a = app_clone
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project_a.id))
                    .header("Authorization", format!("Bearer {}", org_scoped_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_a.status(),
            StatusCode::OK,
            "Org-scoped key should access project_a"
        );

        let response_b = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project_b.id))
                    .header("Authorization", format!("Bearer {}", org_scoped_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_b.status(),
            StatusCode::OK,
            "Org-scoped key should access project_b"
        );
    }

    /// Verify that a project-scoped key cannot access org-level endpoints.
    /// Project scope should not elevate to org-level access.
    #[tokio::test]
    async fn test_project_scoped_key_cannot_access_org_level_endpoints() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create org with a project
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        // Create user as org owner
        let (user, _member, _unscoped_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Create API key with project-level scope only
        let project_scoped_key = create_api_key_with_project_scope(
            &conn,
            &user.id,
            &org.id,
            &project.id,
            AccessLevel::Admin,
        );

        // Try to access org-level endpoint (member management)
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", project_scoped_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Project-scoped key should not access org-level endpoints"
        );
    }

    /// Verify that a read-only (View) scope cannot perform write operations.
    /// This ensures principle of least privilege is enforced.
    #[tokio::test]
    async fn test_read_only_scope_cannot_write() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create org and project
        let org = create_test_org(&conn, "Test Org");
        let _project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        // Create user as org owner
        let (user, _member, _unscoped_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Create a new user to add (for testing the POST)
        let new_user = create_test_user(&conn, "new@test.com", "New User");

        // Create API key with view-only (read) scope
        let view_only_key =
            create_api_key_with_org_scope(&conn, &user.id, &org.id, AccessLevel::View);

        // Try to create a new org member (write operation)
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", view_only_key))
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
            "View-only scope should not allow write operations"
        );
    }

    /// Verify that an unscoped key can access any org the user is a member of.
    /// This is the default behavior when no scopes are defined.
    #[tokio::test]
    async fn test_unscoped_key_has_full_access() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create two organizations
        let org_a = create_test_org(&conn, "Org A");
        let org_b = create_test_org(&conn, "Org B");

        // Create user as member of both orgs (with the default unscoped key)
        let (user, _member_a, unscoped_key) =
            create_test_org_member(&conn, &org_a.id, "user@test.com", OrgMemberRole::Owner);

        // Add user to org_b as well
        queries::create_org_member(
            &conn,
            &org_b.id,
            &paycheck::models::CreateOrgMember {
                user_id: user.id.clone(),
                role: OrgMemberRole::Owner,
            },
        )
        .unwrap();

        // Access org_a with unscoped key
        let app_clone = app.clone();
        let response_a = app_clone
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org_a.id))
                    .header("Authorization", format!("Bearer {}", unscoped_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_a.status(),
            StatusCode::OK,
            "Unscoped key should access org_a"
        );

        // Access org_b with unscoped key
        let response_b = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org_b.id))
                    .header("Authorization", format!("Bearer {}", unscoped_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_b.status(),
            StatusCode::OK,
            "Unscoped key should access org_b (user is a member)"
        );
    }
}

// ============================================================================
// EDGE CASES - DELETED USERS AND ORG MEMBERS
// ============================================================================

mod deleted_entity_tests {
    use super::*;

    /// Verify that an API key belonging to a soft-deleted user is rejected.
    /// This is critical - deleted users must not have any access.
    #[tokio::test]
    async fn test_api_key_of_deleted_user_returns_unauthorized() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create org and member
        let org = create_test_org(&conn, "Test Org");
        let (user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Verify the key works before deletion
        let response_before = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_before.status(),
            StatusCode::OK,
            "Key should work before user deletion"
        );

        // Soft-delete the user
        queries::soft_delete_user(&conn, &user.id).expect("Failed to soft-delete user");

        // Try to use the API key after user deletion
        let response_after = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_after.status(),
            StatusCode::UNAUTHORIZED,
            "API key of deleted user should return 401 Unauthorized"
        );
    }

    /// Verify that a user removed from an org cannot access that org.
    /// This tests org membership revocation.
    #[tokio::test]
    async fn test_api_key_of_deleted_org_member_returns_unauthorized() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create org
        let org = create_test_org(&conn, "Test Org");

        // Create user and make them an org member
        let (user, member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Create another owner so we can delete the first one
        let (_user2, _member2, _key2) =
            create_test_org_member(&conn, &org.id, "owner2@test.com", OrgMemberRole::Owner);

        // Verify the key works before removal
        let response_before = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_before.status(),
            StatusCode::OK,
            "Key should work before org member removal"
        );

        // Remove the user from the org (soft-delete the org member)
        queries::soft_delete_org_member(&conn, &member.id)
            .expect("Failed to soft-delete org member");

        // User still exists, but is no longer a member of this org
        let user_still_exists = queries::get_user_by_id(&conn, &user.id).unwrap();
        assert!(
            user_still_exists.is_some(),
            "User record should persist after org membership removal (soft delete removes membership, not user)"
        );

        // Try to access org with the key (user is no longer a member)
        let response_after = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_after.status(),
            StatusCode::FORBIDDEN,
            "Removed org member should get 403 Forbidden (not a member of this org)"
        );
    }
}
