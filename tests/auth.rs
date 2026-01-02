//! Authorization and permission tests for all protected API endpoints.
//!
//! These tests verify that:
//! 1. Missing/invalid tokens return 401 Unauthorized
//! 2. Role-based access control is enforced (403 Forbidden)
//! 3. Cross-org and cross-project access is blocked
//! 4. Project-level permissions (can_write_project) work correctly

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

mod common;
use common::*;

use paycheck::db::AppState;
use paycheck::handlers;
use paycheck::models::{CreateProjectMember, OperatorRole, OrgMemberRole, ProjectMemberRole};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

// ============================================================================
// Test App Setup Helpers
// ============================================================================

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
        success_page_url: "http://localhost:3000/success".to_string(),
    };

    let app = handlers::operators::router(state.clone()).with_state(state.clone());

    (app, state)
}

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
        success_page_url: "http://localhost:3000/success".to_string(),
    };

    let app = handlers::orgs::router(state.clone()).with_state(state.clone());

    (app, state)
}

// ============================================================================
// OPERATOR API AUTHORIZATION TESTS
// ============================================================================

mod operator_auth {
    use super::*;

    // ------------------------------------------------------------------------
    // Missing/Invalid Token Tests
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn missing_token_returns_401() {
        let (app, _state) = operator_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_token_returns_401() {
        let (app, _state) = operator_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .header("Authorization", "Bearer invalid-token-12345")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_auth_header_returns_401() {
        let (app, _state) = operator_app();

        // Missing "Bearer " prefix
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .header("Authorization", "some-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ------------------------------------------------------------------------
    // Owner-Only Endpoints (/operators/*)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn view_role_cannot_access_operator_list() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_view_op, view_key) = create_test_operator(&conn, "view@test.com", OperatorRole::View);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .header("Authorization", format!("Bearer {}", view_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_role_cannot_access_operator_list() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_admin_op, admin_key) =
            create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn owner_role_can_access_operator_list() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_owner_op, owner_key) =
            create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .header("Authorization", format!("Bearer {}", owner_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_cannot_create_operator() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_admin_op, admin_key) =
            create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators")
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"email": "new@test.com", "name": "New Op", "role": "view"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn owner_can_create_operator() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_owner_op, owner_key) =
            create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators")
                    .header("Authorization", format!("Bearer {}", owner_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"email": "new@test.com", "name": "New Op", "role": "view"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ------------------------------------------------------------------------
    // Admin-Level Endpoints (/operators/organizations/*)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn view_role_cannot_list_organizations() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_view_op, view_key) = create_test_operator(&conn, "view@test.com", OperatorRole::View);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/organizations")
                    .header("Authorization", format!("Bearer {}", view_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_role_can_list_organizations() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_admin_op, admin_key) =
            create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/organizations")
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn owner_role_can_list_organizations() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_owner_op, owner_key) =
            create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/organizations")
                    .header("Authorization", format!("Bearer {}", owner_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn view_cannot_create_organization() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_view_op, view_key) = create_test_operator(&conn, "view@test.com", OperatorRole::View);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators/organizations")
                    .header("Authorization", format!("Bearer {}", view_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name": "New Org"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_can_create_organization() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_admin_op, admin_key) =
            create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators/organizations")
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name": "New Org"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ------------------------------------------------------------------------
    // View-Level Endpoints (/operators/audit-logs)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn view_role_can_access_audit_logs() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_view_op, view_key) = create_test_operator(&conn, "view@test.com", OperatorRole::View);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs")
                    .header("Authorization", format!("Bearer {}", view_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_role_can_access_audit_logs() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        let (_admin_op, admin_key) =
            create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs")
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_token_cannot_access_audit_logs() {
        let (app, _state) = operator_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

// ============================================================================
// ORG MEMBER API AUTHORIZATION TESTS
// ============================================================================

mod org_member_auth {
    use super::*;

    // ------------------------------------------------------------------------
    // Missing/Invalid Token Tests
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn missing_token_returns_401() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_token_returns_401() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", "Bearer invalid-token-12345")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ------------------------------------------------------------------------
    // Cross-Org Access Prevention
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn cannot_access_another_orgs_members() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create two orgs
        let org1 = create_test_org(&conn, "Org 1");
        let org2 = create_test_org(&conn, "Org 2");

        // Create member in org1
        let (_member1, key1) =
            create_test_org_member(&conn, &org1.id, "user@org1.com", OrgMemberRole::Owner);

        // Try to access org2's members with org1's key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org2.id))
                    .header("Authorization", format!("Bearer {}", key1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn cannot_access_another_orgs_projects() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org1 = create_test_org(&conn, "Org 1");
        let org2 = create_test_org(&conn, "Org 2");

        let (_member1, key1) =
            create_test_org_member(&conn, &org1.id, "user@org1.com", OrgMemberRole::Owner);

        // Create a project in org2
        let project2 = create_test_project(&conn, &org2.id, "Org2 Project", &state.master_key);

        // Try to access org2's project with org1's key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org2.id, project2.id))
                    .header("Authorization", format!("Bearer {}", key1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ------------------------------------------------------------------------
    // Org Member Role Checks (Owner-Only Operations)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn member_role_cannot_create_org_member() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"email": "new@org.com", "name": "New Member", "role": "member"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_role_cannot_create_org_member() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_admin, admin_key) =
            create_test_org_member(&conn, &org.id, "admin@org.com", OrgMemberRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"email": "new@org.com", "name": "New Member", "role": "member"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn owner_role_can_create_org_member() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_owner, owner_key) =
            create_test_org_member(&conn, &org.id, "owner@org.com", OrgMemberRole::Owner);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", owner_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"email": "new@org.com", "name": "New Member", "role": "member"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn member_cannot_update_org_member() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (target, _target_key) =
            create_test_org_member(&conn, &org.id, "target@org.com", OrgMemberRole::Member);
        let (_member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/orgs/{}/members/{}", org.id, target.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name": "Updated Name"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn member_cannot_delete_org_member() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (target, _target_key) =
            create_test_org_member(&conn, &org.id, "target@org.com", OrgMemberRole::Member);
        let (_member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/members/{}", org.id, target.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ------------------------------------------------------------------------
    // Project Creation (Admin+ Only)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn member_role_cannot_create_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects", org.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name": "New Project", "domain": "test.example.com", "license_key_prefix": "TEST"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_role_can_create_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_admin, admin_key) =
            create_test_org_member(&conn, &org.id, "admin@org.com", OrgMemberRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects", org.id))
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name": "New Project", "domain": "test.example.com", "license_key_prefix": "TEST"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ------------------------------------------------------------------------
    // Read Operations (Any Org Member)
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn member_can_list_org_members() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn member_can_list_projects() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects", org.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}

// ============================================================================
// PROJECT-LEVEL PERMISSION TESTS (can_write_project logic)
// ============================================================================

mod project_permissions {
    use super::*;

    // ------------------------------------------------------------------------
    // Member Without Project Access
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn member_without_project_access_cannot_read_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        // Create a member with no project membership
        let (_member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn member_without_project_access_cannot_list_products() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let (_member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}/products", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ------------------------------------------------------------------------
    // Member With View Project Role
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn member_with_view_role_can_read_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        // Add project membership with View role
        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn member_with_view_role_can_list_products() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}/products", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn member_with_view_role_cannot_create_product() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products",
                        org.id, project.id
                    ))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name": "New Product", "tier": "pro", "activation_limit": 5, "device_limit": 3, "features": []}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn member_with_view_role_cannot_update_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name": "Updated Name"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ------------------------------------------------------------------------
    // Member With Admin Project Role
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn member_with_admin_project_role_can_create_product() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::Admin,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products",
                        org.id, project.id
                    ))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name": "New Product", "tier": "pro", "activation_limit": 5, "device_limit": 3, "features": []}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn member_with_admin_project_role_can_update_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::Admin,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name": "Updated Name"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn member_with_admin_project_role_cannot_delete_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::Admin,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        // Project deletion requires org-level Admin or Owner
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ------------------------------------------------------------------------
    // Org-Level Admin Has Implicit Project Access
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn org_admin_has_implicit_project_write_access() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        // Admin org member - no project_members entry needed
        let (_admin, admin_key) =
            create_test_org_member(&conn, &org.id, "admin@org.com", OrgMemberRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products",
                        org.id, project.id
                    ))
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name": "New Product", "tier": "pro", "activation_limit": 5, "device_limit": 3, "features": []}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn org_owner_has_implicit_project_write_access() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (_owner, owner_key) =
            create_test_org_member(&conn, &org.id, "owner@org.com", OrgMemberRole::Owner);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products",
                        org.id, project.id
                    ))
                    .header("Authorization", format!("Bearer {}", owner_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name": "New Product", "tier": "pro", "activation_limit": 5, "device_limit": 3, "features": []}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn org_admin_can_delete_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (_admin, admin_key) =
            create_test_org_member(&conn, &org.id, "admin@org.com", OrgMemberRole::Admin);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}

// ============================================================================
// CROSS-PROJECT BOUNDARY TESTS
// ============================================================================

mod cross_project_boundaries {
    use super::*;

    #[tokio::test]
    async fn cannot_access_product_from_another_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project1 = create_test_project(&conn, &org.id, "Project 1", &state.master_key);
        let project2 = create_test_project(&conn, &org.id, "Project 2", &state.master_key);

        // Create product in project1
        let product = create_test_product(&conn, &project1.id, "Product 1", "pro");

        let (_owner, owner_key) =
            create_test_org_member(&conn, &org.id, "owner@org.com", OrgMemberRole::Owner);

        // Try to access product1 via project2's URL
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}",
                        org.id, project2.id, product.id
                    ))
                    .header("Authorization", format!("Bearer {}", owner_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should be NOT_FOUND because the product belongs to project1, not project2
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cannot_access_license_from_another_project() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project1 = create_test_project(&conn, &org.id, "Project 1", &state.master_key);
        let project2 = create_test_project(&conn, &org.id, "Project 2", &state.master_key);

        let product = create_test_product(&conn, &project1.id, "Product 1", "pro");
        let license = create_test_license(
            &conn,
            &project1.id,
            &product.id,
            &project1.license_key_prefix,
            None,
            &state.master_key,
        );

        let (_owner, owner_key) =
            create_test_org_member(&conn, &org.id, "owner@org.com", OrgMemberRole::Owner);

        // Try to access license via project2's URL
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}",
                        org.id, project2.id, license.key
                    ))
                    .header("Authorization", format!("Bearer {}", owner_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn member_with_access_to_project1_cannot_access_project2() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project1 = create_test_project(&conn, &org.id, "Project 1", &state.master_key);
        let project2 = create_test_project(&conn, &org.id, "Project 2", &state.master_key);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        // Give member access to project1 only
        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project1.id, &pm_input).unwrap();

        // Should be able to access project1
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project1.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Should NOT be able to access project2
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org.id, project2.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

// ============================================================================
// LICENSE OPERATIONS PERMISSION TESTS
// ============================================================================

mod license_permissions {
    use super::*;

    #[tokio::test]
    async fn member_with_view_role_cannot_create_license() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let _product = create_test_product(&conn, &project.id, "Pro", "pro");

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/licenses", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"product_id": "some-id"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn member_with_view_role_can_list_licenses() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}/licenses", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn member_with_view_role_cannot_revoke_license() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let product = create_test_product(&conn, &project.id, "Pro", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            &project.license_key_prefix,
            None,
            &state.master_key,
        );

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}/revoke",
                        org.id, project.id, license.key
                    ))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn member_with_admin_project_role_can_revoke_license() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let product = create_test_product(&conn, &project.id, "Pro", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            &project.license_key_prefix,
            None,
            &state.master_key,
        );

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::Admin,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}/revoke",
                        org.id, project.id, license.key
                    ))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}

// ============================================================================
// DEVICE MANAGEMENT PERMISSION TESTS
// ============================================================================

mod device_permissions {
    use super::*;
    use paycheck::models::DeviceType;

    #[tokio::test]
    async fn member_with_view_role_cannot_deactivate_device() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let product = create_test_product(&conn, &project.id, "Pro", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            &project.license_key_prefix,
            None,
            &state.master_key,
        );
        let device = create_test_device(&conn, &license.id, "device-123", DeviceType::Uuid);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}/devices/{}",
                        org.id, project.id, license.key, device.device_id
                    ))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn member_with_admin_project_role_can_deactivate_device() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let product = create_test_product(&conn, &project.id, "Pro", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            &project.license_key_prefix,
            None,
            &state.master_key,
        );
        let device = create_test_device(&conn, &license.id, "device-123", DeviceType::Uuid);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::Admin,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}/devices/{}",
                        org.id, project.id, license.key, device.device_id
                    ))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}

// ============================================================================
// PROJECT MEMBER MANAGEMENT PERMISSION TESTS
// ============================================================================

mod project_member_management {
    use super::*;

    #[tokio::test]
    async fn member_with_view_role_cannot_add_project_member() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);
        let (other_member, _) =
            create_test_org_member(&conn, &org.id, "other@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/members", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"org_member_id": "{}", "role": "view"}}"#,
                        other_member.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn member_with_admin_project_role_can_add_project_member() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);
        let (other_member, _) =
            create_test_org_member(&conn, &org.id, "other@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::Admin,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/members", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"org_member_id": "{}", "role": "view"}}"#,
                        other_member.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn member_can_list_project_members_with_view_role() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);

        let (member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let pm_input = CreateProjectMember {
            org_member_id: member.id.clone(),
            role: ProjectMemberRole::View,
        };
        queries::create_project_member(&conn, &project.id, &pm_input).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}/members", org.id, project.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}

// ============================================================================
// ORG-SCOPED AUDIT LOG ISOLATION TESTS
// ============================================================================

mod org_audit_log_isolation {
    use super::*;
    use axum::body::to_bytes;

    /// Creates an org app with audit logging enabled so we can test the audit endpoint
    fn org_app_with_audit() -> (Router, AppState) {
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
            audit_log_enabled: true, // Enable audit logging
            master_key,
            success_page_url: "http://localhost:3000/success".to_string(),
        };

        let app = handlers::orgs::router(state.clone()).with_state(state.clone());

        (app, state)
    }

    #[tokio::test]
    async fn org_member_can_access_own_audit_logs() {
        let (app, state) = org_app_with_audit();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");
        let (_member, member_key) =
            create_test_org_member(&conn, &org.id, "member@org.com", OrgMemberRole::Member);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs", org.id))
                    .header("Authorization", format!("Bearer {}", member_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn org_member_cannot_access_another_orgs_audit_logs() {
        let (app, state) = org_app_with_audit();
        let conn = state.db.get().unwrap();

        // Create two orgs
        let org1 = create_test_org(&conn, "Org 1");
        let org2 = create_test_org(&conn, "Org 2");

        // Create member in org1
        let (_member1, key1) =
            create_test_org_member(&conn, &org1.id, "user@org1.com", OrgMemberRole::Owner);

        // Try to access org2's audit logs with org1's key
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs", org2.id))
                    .header("Authorization", format!("Bearer {}", key1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn audit_logs_only_return_own_org_data() {
        use paycheck::models::ActorType;

        let (app, state) = org_app_with_audit();
        let conn = state.db.get().unwrap();
        let audit_conn = state.audit.get().unwrap();

        // Create two orgs with members
        let org1 = create_test_org(&conn, "Org 1");
        let org2 = create_test_org(&conn, "Org 2");

        let (_member1, key1) =
            create_test_org_member(&conn, &org1.id, "user@org1.com", OrgMemberRole::Owner);
        let (_member2, _key2) =
            create_test_org_member(&conn, &org2.id, "user@org2.com", OrgMemberRole::Owner);

        // Create audit logs for both orgs
        queries::create_audit_log(
            &audit_conn,
            true,
            ActorType::OrgMember,
            Some("member1"),
            "test_action_org1",
            "test_resource",
            "resource1",
            None,
            Some(&org1.id),
            None,
            None,
            None,
        )
        .unwrap();

        queries::create_audit_log(
            &audit_conn,
            true,
            ActorType::OrgMember,
            Some("member2"),
            "test_action_org2",
            "test_resource",
            "resource2",
            None,
            Some(&org2.id),
            None,
            None,
            None,
        )
        .unwrap();

        // Query org1's audit logs
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs", org1.id))
                    .header("Authorization", format!("Bearer {}", key1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let logs: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

        // Should only see org1's log
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0]["action"], "test_action_org1");
        assert_eq!(logs[0]["org_id"], org1.id);
    }

    #[tokio::test]
    async fn query_param_org_id_cannot_override_path_org_id() {
        use paycheck::models::ActorType;

        let (app, state) = org_app_with_audit();
        let conn = state.db.get().unwrap();
        let audit_conn = state.audit.get().unwrap();

        // Create two orgs
        let org1 = create_test_org(&conn, "Org 1");
        let org2 = create_test_org(&conn, "Org 2");

        let (_member1, key1) =
            create_test_org_member(&conn, &org1.id, "user@org1.com", OrgMemberRole::Owner);

        // Create audit logs for both orgs
        queries::create_audit_log(
            &audit_conn,
            true,
            ActorType::OrgMember,
            Some("member1"),
            "org1_action",
            "test_resource",
            "resource1",
            None,
            Some(&org1.id),
            None,
            None,
            None,
        )
        .unwrap();

        queries::create_audit_log(
            &audit_conn,
            true,
            ActorType::OrgMember,
            Some("member2"),
            "org2_action",
            "test_resource",
            "resource2",
            None,
            Some(&org2.id),
            None,
            None,
            None,
        )
        .unwrap();

        // Try to query with org_id query param pointing to org2
        // The path org_id (org1) should take precedence
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs?org_id={}", org1.id, org2.id))
                    .header("Authorization", format!("Bearer {}", key1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let logs: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

        // Should only see org1's log, NOT org2's - path org_id takes precedence
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0]["action"], "org1_action");
        assert_eq!(logs[0]["org_id"], org1.id);
    }

    #[tokio::test]
    async fn missing_token_cannot_access_org_audit_logs() {
        let (app, state) = org_app_with_audit();
        let conn = state.db.get().unwrap();

        let org = create_test_org(&conn, "Test Org");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/audit-logs", org.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
