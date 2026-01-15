//! Soft delete cascade verification tests.
//!
//! These tests verify that soft delete cascades work correctly across the entity hierarchy:
//! - Users cascade to operators, org_members, and API keys
//! - Organizations cascade to projects, products, licenses, and org_members
//! - Projects cascade to products and licenses
//!
//! CRITICAL: These tests ensure data integrity and proper access revocation
//! when entities are deleted. Any failure indicates a potential data leak or
//! orphaned records vulnerability.

#[path = "../common/mod.rs"]
mod common;
use common::{*, ONE_MONTH, LICENSE_VALID_DAYS};

use axum::{Router, body::Body, http::{Request, StatusCode}};
use paycheck::config::RateLimitConfig;
use paycheck::db::{AppState, queries};
use paycheck::handlers;
use paycheck::models::{DeviceType, OrgMemberRole, OperatorRole};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tower::ServiceExt;

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

/// Creates a test app with the full operator router (with middleware).
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

    let app = handlers::operators::router(state.clone())
        .with_state(state.clone());

    (app, state)
}

// ============================================================================
// User Cascade Tests
// ============================================================================

mod user_cascade {
    use super::*;

    /// Delete user -> API keys stop working (via FK CASCADE in SQLite).
    /// API keys reference users with ON DELETE CASCADE, so hard delete removes them.
    /// For soft delete, we verify API key auth fails when user is soft-deleted.
    #[tokio::test]
    async fn test_delete_user_api_keys_stop_working() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create org and member with API key
        let org = create_test_org(&conn, "Test Org");
        let (user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Verify API key works before deletion
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
            "API key should work before user deletion"
        );

        // Soft delete the user
        queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

        // API key should no longer work (user is deleted)
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
            "API key should return 401 after user soft delete"
        );
    }

    /// Delete user -> cascades to org_members (membership revoked).
    #[test]
    fn test_delete_user_cascades_to_org_members() {
        let conn = setup_test_db();
        let org = create_test_org(&conn, "Test Org");
        let (user, member, _api_key) =
            create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);

        // Soft delete the user
        queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

        // Org member should not be found via normal query
        let result = queries::get_org_member_by_id(&conn, &member.id).expect("Query failed");
        assert!(
            result.is_none(),
            "Org member should not be found after user soft delete"
        );

        // Org member should be found via deleted query with depth 1
        let deleted = queries::get_deleted_org_member_by_id(&conn, &member.id)
            .expect("Query failed")
            .expect("Deleted org member should be found");

        assert!(deleted.deleted_at.is_some(), "Org member deleted_at timestamp should be set after cascade delete from user");
        assert_eq!(
            deleted.deleted_cascade_depth,
            Some(1),
            "Org member cascade depth should be 1 when deleted via user cascade"
        );
    }

    /// Delete user -> cascades to operators (if user is operator).
    #[test]
    fn test_delete_user_cascades_to_operators() {
        let conn = setup_test_db();
        let (user, operator, _api_key) =
            create_test_operator(&conn, "operator@test.com", OperatorRole::Admin);

        // Soft delete the user
        queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

        // Operator should not be found via normal query
        let result = queries::get_operator_by_id(&conn, &operator.id).expect("Query failed");
        assert!(
            result.is_none(),
            "Operator record should be excluded from normal queries after parent user is soft deleted"
        );

        // Operator should be found via deleted query with depth 1
        let deleted = queries::get_deleted_operator_by_id(&conn, &operator.id)
            .expect("Query failed")
            .expect("Deleted operator should be found");

        assert!(deleted.deleted_at.is_some(), "Operator deleted_at timestamp should be set after cascade delete from user");
        assert_eq!(
            deleted.deleted_cascade_depth,
            Some(1),
            "Operator cascade depth should be 1 when deleted via user cascade"
        );
    }

    /// Delete user -> operator API key stops working.
    #[tokio::test]
    async fn test_delete_user_operator_api_key_stops_working() {
        let (app, state) = operator_app();
        let conn = state.db.get().unwrap();

        // Create operator with API key
        let (admin_user, _admin_op, admin_key) =
            create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

        // Create another operator to query (so we have something to list)
        create_test_operator(&conn, "other@test.com", OperatorRole::View);

        // Verify API key works before deletion
        let response_before = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/users")
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_before.status(),
            StatusCode::OK,
            "Operator API key should work before user deletion"
        );

        // Soft delete the user
        queries::soft_delete_user(&conn, &admin_user.id).expect("Soft delete failed");

        // API key should no longer work
        let response_after = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/users")
                    .header("Authorization", format!("Bearer {}", admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response_after.status(),
            StatusCode::UNAUTHORIZED,
            "Operator API key should return 401 after user soft delete"
        );
    }
}

// ============================================================================
// Organization Cascade Tests
// ============================================================================

mod org_cascade {
    use super::*;

    /// Delete org -> cascades to projects, products, licenses.
    #[test]
    fn test_delete_org_cascades_to_projects_products_licenses() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        // Soft delete the organization
        queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

        // Org should not be found via normal query
        assert!(
            queries::get_organization_by_id(&conn, &org.id)
                .expect("Query failed")
                .is_none(),
            "Organization should be excluded from normal queries after soft delete"
        );

        // Project should be cascade deleted (depth 1)
        let deleted_project = queries::get_deleted_project_by_id(&conn, &project.id)
            .expect("Query failed")
            .expect("Deleted project should be found");
        assert_eq!(deleted_project.deleted_cascade_depth, Some(1), "Project cascade depth should be 1 when deleted via org cascade");

        // Product should be cascade deleted (depth 2)
        let deleted_product = queries::get_deleted_product_by_id(&conn, &product.id)
            .expect("Query failed")
            .expect("Deleted product should be found");
        assert_eq!(deleted_product.deleted_cascade_depth, Some(2), "Product cascade depth should be 2 when deleted via org->project cascade");

        // License should be cascade deleted (depth 3)
        let deleted_license = queries::get_deleted_license_by_id(&conn, &license.id)
            .expect("Query failed")
            .expect("Deleted license should be found");
        assert_eq!(deleted_license.deleted_cascade_depth, Some(3), "License cascade depth should be 3 when deleted via org->project->product cascade");
    }

    /// Delete org -> cascades to org_members.
    #[test]
    fn test_delete_org_cascades_to_org_members() {
        let conn = setup_test_db();
        let org = create_test_org(&conn, "Test Org");
        let (_user, member, _api_key) =
            create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);

        // Soft delete the organization
        queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

        // Org member should not be found via normal query
        assert!(
            queries::get_org_member_by_id(&conn, &member.id)
                .expect("Query failed")
                .is_none(),
            "Org member should be excluded from normal queries after parent org is soft deleted"
        );

        // Org member should be cascade deleted (depth 1)
        let deleted_member = queries::get_deleted_org_member_by_id(&conn, &member.id)
            .expect("Query failed")
            .expect("Deleted member should be found");
        assert_eq!(deleted_member.deleted_cascade_depth, Some(1), "Org member cascade depth should be 1 when deleted via org cascade");
    }

    /// Delete org -> API keys for org members stop working for that org.
    #[tokio::test]
    async fn test_delete_org_api_keys_stop_working_for_org() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create org with a member
        let org = create_test_org(&conn, "Test Org");
        let (_user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);

        // Verify API key works before deletion
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
            "API key should work before org deletion"
        );

        // Soft delete the organization
        queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

        // API key should still be valid but org access is gone
        // (the user exists, but org is deleted so 404 for the org)
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

        // Should be 403 or 404 since org is deleted and membership is cascade deleted
        assert!(
            response_after.status() == StatusCode::FORBIDDEN
                || response_after.status() == StatusCode::NOT_FOUND,
            "API key should return 403 or 404 for deleted org, got {}",
            response_after.status()
        );
    }

    /// Delete org with multiple projects - all cascade correctly.
    #[test]
    fn test_delete_org_multiple_projects_cascade() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");

        // Create multiple projects with products and licenses
        let project1 = create_test_project(&conn, &org.id, "Project 1", &master_key);
        let product1 = create_test_product(&conn, &project1.id, "Pro 1", "pro");
        let license1 =
            create_test_license(&conn, &project1.id, &product1.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        let project2 = create_test_project(&conn, &org.id, "Project 2", &master_key);
        let product2 = create_test_product(&conn, &project2.id, "Pro 2", "pro");
        let license2 =
            create_test_license(&conn, &project2.id, &product2.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        // Soft delete the organization
        queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

        // All projects should be cascade deleted at depth 1
        assert_eq!(
            queries::get_deleted_project_by_id(&conn, &project1.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(1),
            "Project 1 cascade depth should be 1 when deleted via org cascade"
        );
        assert_eq!(
            queries::get_deleted_project_by_id(&conn, &project2.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(1),
            "Project 2 cascade depth should be 1 when deleted via org cascade"
        );

        // All products at depth 2
        assert_eq!(
            queries::get_deleted_product_by_id(&conn, &product1.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(2),
            "Product 1 cascade depth should be 2 when deleted via org->project cascade"
        );
        assert_eq!(
            queries::get_deleted_product_by_id(&conn, &product2.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(2),
            "Product 2 cascade depth should be 2 when deleted via org->project cascade"
        );

        // All licenses at depth 3
        assert_eq!(
            queries::get_deleted_license_by_id(&conn, &license1.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(3),
            "License 1 cascade depth should be 3 when deleted via org->project->product cascade"
        );
        assert_eq!(
            queries::get_deleted_license_by_id(&conn, &license2.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(3),
            "License 2 cascade depth should be 3 when deleted via org->project->product cascade"
        );
    }
}

// ============================================================================
// Project Cascade Tests
// ============================================================================

mod project_cascade {
    use super::*;

    /// Delete project -> cascades to products and licenses.
    #[test]
    fn test_delete_project_cascades_to_products_and_licenses() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        // Soft delete the project
        queries::soft_delete_project(&conn, &project.id).expect("Soft delete failed");

        // Project deleted at depth 0
        let deleted_project = queries::get_deleted_project_by_id(&conn, &project.id)
            .expect("Query failed")
            .expect("Deleted project should be found");
        assert_eq!(deleted_project.deleted_cascade_depth, Some(0), "Directly deleted project should have cascade depth 0");

        // Product cascade deleted at depth 1
        let deleted_product = queries::get_deleted_product_by_id(&conn, &product.id)
            .expect("Query failed")
            .expect("Deleted product should be found");
        assert_eq!(deleted_product.deleted_cascade_depth, Some(1), "Product cascade depth should be 1 when deleted via project cascade");

        // License cascade deleted at depth 2
        let deleted_license = queries::get_deleted_license_by_id(&conn, &license.id)
            .expect("Query failed")
            .expect("Deleted license should be found");
        assert_eq!(deleted_license.deleted_cascade_depth, Some(2), "License cascade depth should be 2 when deleted via project->product cascade");
    }

    /// Delete project with multiple products - all cascade correctly.
    #[test]
    fn test_delete_project_multiple_products_cascade() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

        // Create multiple products
        let product1 = create_test_product(&conn, &project.id, "Free", "free");
        let product2 = create_test_product(&conn, &project.id, "Pro", "pro");
        let product3 = create_test_product(&conn, &project.id, "Enterprise", "enterprise");

        // Create licenses for each
        let license1 =
            create_test_license(&conn, &project.id, &product1.id, Some(future_timestamp(LICENSE_VALID_DAYS)));
        let license2 =
            create_test_license(&conn, &project.id, &product2.id, Some(future_timestamp(LICENSE_VALID_DAYS)));
        let license3 =
            create_test_license(&conn, &project.id, &product3.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        // Soft delete the project
        queries::soft_delete_project(&conn, &project.id).expect("Soft delete failed");

        // All products should be cascade deleted at depth 1
        for product_id in [&product1.id, &product2.id, &product3.id] {
            let deleted = queries::get_deleted_product_by_id(&conn, product_id)
                .unwrap()
                .unwrap();
            assert_eq!(deleted.deleted_cascade_depth, Some(1), "Product cascade depth should be 1 when deleted via project cascade");
        }

        // All licenses should be cascade deleted at depth 2
        for license_id in [&license1.id, &license2.id, &license3.id] {
            let deleted = queries::get_deleted_license_by_id(&conn, license_id)
                .unwrap()
                .unwrap();
            assert_eq!(deleted.deleted_cascade_depth, Some(2), "License cascade depth should be 2 when deleted via project->product cascade");
        }
    }

    /// Delete project -> devices and activation codes are not directly cascade-deleted
    /// but become inaccessible via their parent license.
    #[test]
    fn test_delete_project_devices_inaccessible() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        // Create device for license
        let _device = create_test_device(&conn, &license.id, "device-123", DeviceType::Machine);

        // Soft delete the project
        queries::soft_delete_project(&conn, &project.id).expect("Soft delete failed");

        // License is cascade deleted
        assert!(
            queries::get_license_by_id(&conn, &license.id)
                .unwrap()
                .is_none(),
            "License should be excluded from normal queries after parent project is soft deleted"
        );

        // Devices still exist in DB but become orphaned - can be verified by listing
        // (devices don't have soft delete - they're cleaned up via FK CASCADE on hard delete)
        let devices = queries::list_devices_for_license(&conn, &license.id).expect("Query failed");
        assert!(
            !devices.is_empty(),
            "Devices should still exist in DB since they don't have soft delete"
        );
    }
}

// ============================================================================
// Restore Cascade Tests
// ============================================================================

mod restore_cascade {
    use super::*;

    /// Restore user -> restores cascaded operators and org_members.
    #[test]
    fn test_restore_user_restores_cascaded_children() {
        let conn = setup_test_db();
        let org = create_test_org(&conn, "Test Org");
        let (user, member, _api_key) =
            create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);

        // Also make user an operator
        let operator = {
            let input = paycheck::models::CreateOperator {
                user_id: user.id.clone(),
                role: OperatorRole::View,
            };
            queries::create_operator(&conn, &input).expect("Failed to create operator")
        };

        // Soft delete the user (cascades to operator and org_member)
        queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

        // Verify both are deleted
        assert!(queries::get_operator_by_id(&conn, &operator.id).unwrap().is_none(), "Operator should be excluded from normal queries after user soft delete");
        assert!(queries::get_org_member_by_id(&conn, &member.id).unwrap().is_none(), "Org member should be excluded from normal queries after user soft delete");

        // Restore the user
        queries::restore_user(&conn, &user.id, false).expect("Restore failed");

        // Both should be restored
        assert!(
            queries::get_operator_by_id(&conn, &operator.id)
                .unwrap()
                .is_some(),
            "Operator should be restored"
        );
        assert!(
            queries::get_org_member_by_id(&conn, &member.id)
                .unwrap()
                .is_some(),
            "Org member should be restored"
        );
    }

    /// Restore org -> restores cascaded projects/products/licenses.
    #[test]
    fn test_restore_org_restores_entire_hierarchy() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let (_user, member, _api_key) =
            create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        // Soft delete the organization (cascades to all children)
        queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

        // Verify all are deleted
        assert!(queries::get_organization_by_id(&conn, &org.id).unwrap().is_none(), "Organization should be excluded from normal queries after soft delete");
        assert!(queries::get_org_member_by_id(&conn, &member.id).unwrap().is_none(), "Org member should be excluded after org cascade delete");
        assert!(queries::get_project_by_id(&conn, &project.id).unwrap().is_none(), "Project should be excluded after org cascade delete");
        assert!(queries::get_product_by_id(&conn, &product.id).unwrap().is_none(), "Product should be excluded after org cascade delete");
        assert!(queries::get_license_by_id(&conn, &license.id).unwrap().is_none(), "License should be excluded after org cascade delete");

        // Restore the organization
        queries::restore_organization(&conn, &org.id).expect("Restore failed");

        // All entities should be restored
        assert!(
            queries::get_organization_by_id(&conn, &org.id)
                .unwrap()
                .is_some(),
            "Organization should be accessible after restore"
        );
        assert!(
            queries::get_org_member_by_id(&conn, &member.id)
                .unwrap()
                .is_some(),
            "Org member should be restored when parent org is restored"
        );
        assert!(
            queries::get_project_by_id(&conn, &project.id)
                .unwrap()
                .is_some(),
            "Project should be restored when parent org is restored"
        );
        assert!(
            queries::get_product_by_id(&conn, &product.id)
                .unwrap()
                .is_some(),
            "Product should be restored when parent org is restored"
        );
        assert!(
            queries::get_license_by_id(&conn, &license.id)
                .unwrap()
                .is_some(),
            "License should be restored when parent org is restored"
        );
    }

    /// Force restore of cascade-deleted item works.
    #[test]
    fn test_force_restore_cascade_deleted_item() {
        let conn = setup_test_db();
        let (user, operator, _api_key) =
            create_test_operator(&conn, "operator@test.com", OperatorRole::Admin);

        // Soft delete the user (cascades to operator with depth 1)
        queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

        // Restore operator without force should fail (depth > 0)
        let result = queries::restore_operator(&conn, &operator.id, false);
        assert!(
            result.is_err(),
            "Restore without force should fail for cascade-deleted operator (depth > 0)"
        );

        // Restore operator with force should succeed
        let result = queries::restore_operator(&conn, &operator.id, true);
        assert!(result.is_ok(), "Restore with force=true should succeed even for cascade-deleted items");

        // Operator should be found again (but user is still deleted)
        let restored = queries::get_operator_by_id(&conn, &operator.id)
            .expect("Query failed")
            .expect("Restored operator should be found");
        assert!(restored.deleted_at.is_none(), "Restored operator's deleted_at should be cleared");
    }

    /// Restore project -> restores products and licenses.
    #[test]
    fn test_restore_project_restores_products_and_licenses() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        // Soft delete the project
        queries::soft_delete_project(&conn, &project.id).expect("Soft delete failed");

        // Restore the project
        queries::restore_project(&conn, &project.id, false).expect("Restore failed");

        // All entities should be restored
        assert!(
            queries::get_project_by_id(&conn, &project.id)
                .unwrap()
                .is_some(),
            "Project should be accessible after restore"
        );
        assert!(
            queries::get_product_by_id(&conn, &product.id)
                .unwrap()
                .is_some(),
            "Product should be restored when parent project is restored"
        );
        assert!(
            queries::get_license_by_id(&conn, &license.id)
                .unwrap()
                .is_some(),
            "License should be restored when parent project is restored"
        );
    }

    /// Restore only restores items cascade-deleted at the same time
    /// (items deleted separately remain deleted).
    #[test]
    fn test_restore_selective_by_timestamp() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product1 = create_test_product(&conn, &project.id, "Product 1", "tier1");
        let product2 = create_test_product(&conn, &project.id, "Product 2", "tier2");

        // Soft delete product1 directly
        queries::soft_delete_product(&conn, &product1.id).expect("Soft delete failed");

        // Wait a tiny bit to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Soft delete project (cascades to product2, not product1 which is already deleted)
        queries::soft_delete_project(&conn, &project.id).expect("Soft delete failed");

        // Restore project - should only restore product2 (cascade-deleted with project)
        // product1 was deleted separately and should stay deleted
        queries::restore_project(&conn, &project.id, false).expect("Restore failed");

        // Project should be restored
        assert!(
            queries::get_project_by_id(&conn, &project.id)
                .unwrap()
                .is_some(),
            "Project should be accessible after restore"
        );

        // Product2 should be restored (was cascade-deleted with project)
        assert!(
            queries::get_product_by_id(&conn, &product2.id)
                .unwrap()
                .is_some(),
            "Product 2 should be restored since it was cascade-deleted with the project"
        );

        // Product1 should still be deleted (was deleted separately before project)
        assert!(
            queries::get_product_by_id(&conn, &product1.id)
                .unwrap()
                .is_none(),
            "Product 1 should remain deleted since it was deleted separately before project"
        );
    }

    /// Restore user -> API keys work again.
    #[tokio::test]
    async fn test_restore_user_api_keys_work_again() {
        let (app, state) = org_app();
        let conn = state.db.get().unwrap();

        // Create org and member
        let org = create_test_org(&conn, "Test Org");
        let (user, _member, api_key) =
            create_test_org_member(&conn, &org.id, "user@test.com", OrgMemberRole::Owner);

        // Soft delete the user
        queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

        // Verify key doesn't work
        let response_deleted = app
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
        assert_eq!(response_deleted.status(), StatusCode::UNAUTHORIZED, "API key should return 401 when user is soft deleted");

        // Restore the user
        queries::restore_user(&conn, &user.id, false).expect("Restore failed");

        // API key should work again
        let response_restored = app
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
            response_restored.status(),
            StatusCode::OK,
            "API key should work after user restoration"
        );
    }
}

// ============================================================================
// Purge Verification Tests
// ============================================================================

mod purge_verification {
    use super::*;

    /// Purge old soft-deleted records works correctly.
    #[test]
    fn test_purge_removes_old_soft_deleted_records() {
        let conn = setup_test_db();
        let org = create_test_org(&conn, "Old Deleted Org");

        // Soft delete the org
        queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

        // Manually set deleted_at to 100 days ago to simulate old deletion
        let old_timestamp = now() - (100 * 86400);
        conn.execute(
            "UPDATE organizations SET deleted_at = ?1 WHERE id = ?2",
            rusqlite::params![old_timestamp, org.id],
        )
        .expect("Update timestamp failed");

        // Purge with 30 day retention
        let result = queries::purge_soft_deleted_records(&conn, ONE_MONTH).expect("Purge failed");

        // Should have purged the organization
        assert!(result.organizations > 0, "Purge should have removed organizations older than retention period");

        // Org should be completely gone (not even as deleted)
        let gone = queries::get_deleted_organization_by_id(&conn, &org.id).expect("Query failed");
        assert!(
            gone.is_none(),
            "Organization should be permanently removed from database after purge"
        );
    }

    /// Purge respects retention period (recent deletes not purged).
    #[test]
    fn test_purge_respects_retention_period() {
        let conn = setup_test_db();
        let old_org = create_test_org(&conn, "Old Org");
        let recent_org = create_test_org(&conn, "Recent Org");

        // Soft delete both
        queries::soft_delete_organization(&conn, &old_org.id).expect("Soft delete failed");
        queries::soft_delete_organization(&conn, &recent_org.id).expect("Soft delete failed");

        // Set old_org to 100 days ago
        let old_timestamp = now() - (100 * 86400);
        conn.execute(
            "UPDATE organizations SET deleted_at = ?1 WHERE id = ?2",
            rusqlite::params![old_timestamp, old_org.id],
        )
        .expect("Update timestamp failed");

        // Purge with 30 day retention
        queries::purge_soft_deleted_records(&conn, ONE_MONTH).expect("Purge failed");

        // Old org should be gone
        assert!(
            queries::get_deleted_organization_by_id(&conn, &old_org.id)
                .expect("Query failed")
                .is_none(),
            "Organization deleted 100 days ago should be purged with 30-day retention"
        );

        // Recent org should still exist (as deleted)
        assert!(
            queries::get_deleted_organization_by_id(&conn, &recent_org.id)
                .expect("Query failed")
                .is_some(),
            "Recently deleted organization should be preserved within retention period"
        );
    }

    /// Purge removes entire cascade hierarchy when old enough.
    #[test]
    fn test_purge_removes_entire_hierarchy() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        // Soft delete organization (cascades to all)
        queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

        // Set all to old timestamp
        let old_timestamp = now() - (100 * 86400);
        conn.execute(
            "UPDATE organizations SET deleted_at = ?1",
            rusqlite::params![old_timestamp],
        )
        .unwrap();
        conn.execute(
            "UPDATE projects SET deleted_at = ?1",
            rusqlite::params![old_timestamp],
        )
        .unwrap();
        conn.execute(
            "UPDATE products SET deleted_at = ?1",
            rusqlite::params![old_timestamp],
        )
        .unwrap();
        conn.execute(
            "UPDATE licenses SET deleted_at = ?1",
            rusqlite::params![old_timestamp],
        )
        .unwrap();

        // Purge
        let result = queries::purge_soft_deleted_records(&conn, ONE_MONTH).expect("Purge failed");

        // All should be purged
        assert!(result.licenses > 0, "Purge should have removed licenses");
        assert!(result.products > 0, "Purge should have removed products");
        assert!(result.projects > 0, "Purge should have removed projects");
        assert!(result.organizations > 0, "Purge should have removed organizations");

        // Verify nothing remains
        assert!(
            queries::get_deleted_license_by_id(&conn, &license.id)
                .expect("Query failed")
                .is_none(),
            "License should be permanently removed after purge"
        );
        assert!(
            queries::get_deleted_product_by_id(&conn, &product.id)
                .expect("Query failed")
                .is_none(),
            "Product should be permanently removed after purge"
        );
        assert!(
            queries::get_deleted_project_by_id(&conn, &project.id)
                .expect("Query failed")
                .is_none(),
            "Project should be permanently removed after purge"
        );
        assert!(
            queries::get_deleted_organization_by_id(&conn, &org.id)
                .expect("Query failed")
                .is_none(),
            "Organization should be permanently removed after purge"
        );
    }

    /// Purge cleans up users and their cascade-deleted children.
    #[test]
    fn test_purge_users_and_cascaded_children() {
        let conn = setup_test_db();
        let org = create_test_org(&conn, "Test Org");
        let (user, member, _api_key) =
            create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);

        // Soft delete user (cascades to org_member)
        queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

        // Set to old timestamp
        let old_timestamp = now() - (100 * 86400);
        conn.execute(
            "UPDATE users SET deleted_at = ?1 WHERE id = ?2",
            rusqlite::params![old_timestamp, user.id],
        )
        .unwrap();
        conn.execute(
            "UPDATE org_members SET deleted_at = ?1 WHERE id = ?2",
            rusqlite::params![old_timestamp, member.id],
        )
        .unwrap();

        // Purge
        let result = queries::purge_soft_deleted_records(&conn, ONE_MONTH).expect("Purge failed");

        // Both should be purged
        assert!(result.users > 0, "Purge should have removed users");
        assert!(result.org_members > 0, "Purge should have removed org members");

        // Verify completely gone
        assert!(
            queries::get_deleted_user_by_id(&conn, &user.id)
                .expect("Query failed")
                .is_none(),
            "User should be permanently removed after purge"
        );
        assert!(
            queries::get_deleted_org_member_by_id(&conn, &member.id)
                .expect("Query failed")
                .is_none(),
            "Org member should be permanently removed after purge"
        );
    }
}

// ============================================================================
// List Query Filtering Tests
// ============================================================================

mod list_query_filtering {
    use super::*;

    /// Deleted users don't appear in list queries (by default).
    #[test]
    fn test_deleted_users_excluded_from_list() {
        let conn = setup_test_db();
        create_test_operator(&conn, "active1@example.com", OperatorRole::Admin);
        let (user_to_delete, _op, _key) =
            create_test_operator(&conn, "deleted@example.com", OperatorRole::Admin);
        create_test_operator(&conn, "active2@example.com", OperatorRole::Admin);

        // Soft delete one user
        queries::soft_delete_user(&conn, &user_to_delete.id).expect("Soft delete failed");

        // List should exclude deleted user (include_deleted = false)
        let (users, total) =
            queries::list_users_paginated(&conn, 100, 0, false).expect("Query failed");
        assert_eq!(total, 2, "User count should be 2, excluding soft-deleted user");
        assert_eq!(users.len(), 2, "Returned user list should have 2 entries");
        assert!(users.iter().all(|u| u.email != "deleted@example.com"), "Soft-deleted user should not appear in list results");
    }

    /// Deleted orgs don't appear in list queries (by default).
    #[test]
    fn test_deleted_orgs_excluded_from_list() {
        let conn = setup_test_db();
        create_test_org(&conn, "Active Org 1");
        let org_to_delete = create_test_org(&conn, "Deleted Org");
        create_test_org(&conn, "Active Org 2");

        // Soft delete one org
        queries::soft_delete_organization(&conn, &org_to_delete.id).expect("Soft delete failed");

        // List should exclude deleted org (include_deleted = false)
        let (orgs, total) =
            queries::list_organizations_paginated(&conn, 100, 0, false).expect("Query failed");
        assert_eq!(total, 2, "Organization count should be 2, excluding soft-deleted org");
        assert_eq!(orgs.len(), 2, "Returned org list should have 2 entries");
        assert!(orgs.iter().all(|o| o.name != "Deleted Org"), "Soft-deleted org should not appear in list results");
    }

    /// Deleted projects don't appear in list queries.
    #[test]
    fn test_deleted_projects_excluded_from_list() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");

        create_test_project(&conn, &org.id, "Active Project 1", &master_key);
        let project_to_delete = create_test_project(&conn, &org.id, "Deleted Project", &master_key);
        create_test_project(&conn, &org.id, "Active Project 2", &master_key);

        // Soft delete one project
        queries::soft_delete_project(&conn, &project_to_delete.id).expect("Soft delete failed");

        // List should exclude deleted project
        let (projects, total) =
            queries::list_projects_for_org_paginated(&conn, &org.id, 100, 0).expect("Query failed");
        assert_eq!(total, 2, "Project count should be 2, excluding soft-deleted project");
        assert_eq!(projects.len(), 2, "Returned project list should have 2 entries");
        assert!(projects.iter().all(|p| p.name != "Deleted Project"), "Soft-deleted project should not appear in list results");
    }

    /// Deleted products don't appear in list queries.
    #[test]
    fn test_deleted_products_excluded_from_list() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

        create_test_product(&conn, &project.id, "Active Product 1", "free");
        let product_to_delete = create_test_product(&conn, &project.id, "Deleted Product", "pro");
        create_test_product(&conn, &project.id, "Active Product 2", "enterprise");

        // Soft delete one product
        queries::soft_delete_product(&conn, &product_to_delete.id).expect("Soft delete failed");

        // List should exclude deleted product
        let (products, total) =
            queries::list_products_for_project_paginated(&conn, &project.id, 100, 0).expect("Query failed");
        assert_eq!(total, 2, "Product count should be 2, excluding soft-deleted product");
        assert_eq!(products.len(), 2, "Returned product list should have 2 entries");
        assert!(products.iter().all(|p| p.name != "Deleted Product"), "Soft-deleted product should not appear in list results");
    }

    /// Deleted licenses don't appear in list queries.
    #[test]
    fn test_deleted_licenses_excluded_from_list() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro", "pro");

        let license1 =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(LICENSE_VALID_DAYS)));
        let license_to_delete =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(LICENSE_VALID_DAYS)));
        let license3 =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        // Soft delete one license
        queries::soft_delete_license(&conn, &license_to_delete.id).expect("Soft delete failed");

        // List should exclude deleted license
        // list_licenses_for_project_paginated returns LicenseWithProduct
        let (licenses, total) =
            queries::list_licenses_for_project_paginated(&conn, &project.id, 100, 0).expect("Query failed");
        assert_eq!(total, 2, "License count should be 2, excluding soft-deleted license");
        assert_eq!(licenses.len(), 2, "Returned license list should have 2 entries");
        assert!(licenses.iter().all(|l| l.license.id != license_to_delete.id), "Soft-deleted license should not appear in list results");

        // Verify the two remaining are the expected ones
        let license_ids: Vec<&str> = licenses.iter().map(|l| l.license.id.as_str()).collect();
        assert!(license_ids.contains(&license1.id.as_str()), "License 1 should be in the list");
        assert!(license_ids.contains(&license3.id.as_str()), "License 3 should be in the list");
    }

    /// Include deleted flag shows deleted entities in list.
    #[test]
    fn test_include_deleted_shows_deleted_users() {
        let conn = setup_test_db();
        create_test_operator(&conn, "active@example.com", OperatorRole::Admin);
        let (user_to_delete, _op, _key) =
            create_test_operator(&conn, "deleted@example.com", OperatorRole::Admin);

        // Soft delete one user
        queries::soft_delete_user(&conn, &user_to_delete.id).expect("Soft delete failed");

        // List with include_deleted=true should include all users
        let (users, total) =
            queries::list_users_paginated(&conn, 100, 0, true).expect("Query failed");
        assert_eq!(total, 2, "Total user count with include_deleted=true should be 2");
        assert_eq!(users.len(), 2, "Returned user list with include_deleted=true should have 2 entries");
        assert!(users.iter().any(|u| u.email == "deleted@example.com"), "Soft-deleted user should appear when include_deleted=true");
    }

    /// Include deleted flag shows deleted orgs in list.
    #[test]
    fn test_include_deleted_shows_deleted_orgs() {
        let conn = setup_test_db();
        create_test_org(&conn, "Active Org");
        let org_to_delete = create_test_org(&conn, "Deleted Org");

        // Soft delete one org
        queries::soft_delete_organization(&conn, &org_to_delete.id).expect("Soft delete failed");

        // List with include_deleted=true should include all orgs
        let (orgs, total) =
            queries::list_organizations_paginated(&conn, 100, 0, true).expect("Query failed");
        assert_eq!(total, 2, "Total org count with include_deleted=true should be 2");
        assert_eq!(orgs.len(), 2, "Returned org list with include_deleted=true should have 2 entries");
        assert!(orgs.iter().any(|o| o.name == "Deleted Org"), "Soft-deleted org should appear when include_deleted=true");
    }
}

// ============================================================================
// Cascade Depth Tracking Tests
// ============================================================================

mod cascade_depth_tracking {
    use super::*;

    /// Direct delete sets depth to 0.
    #[test]
    fn test_direct_delete_depth_zero() {
        let conn = setup_test_db();
        let org = create_test_org(&conn, "Test Org");

        queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

        let deleted = queries::get_deleted_organization_by_id(&conn, &org.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            deleted.deleted_cascade_depth,
            Some(0),
            "Directly deleted organization should have cascade depth 0"
        );
    }

    /// Cascade from user sets depth correctly (operators and org_members at depth 1).
    #[test]
    fn test_user_cascade_depth() {
        let conn = setup_test_db();
        let org = create_test_org(&conn, "Test Org");
        let (user, member, _api_key) =
            create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);

        // Also make user an operator
        let operator = {
            let input = paycheck::models::CreateOperator {
                user_id: user.id.clone(),
                role: OperatorRole::View,
            };
            queries::create_operator(&conn, &input).expect("Failed to create operator")
        };

        queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

        // User at depth 0
        let deleted_user = queries::get_deleted_user_by_id(&conn, &user.id)
            .unwrap()
            .unwrap();
        assert_eq!(deleted_user.deleted_cascade_depth, Some(0), "Directly deleted user should have cascade depth 0");

        // Operator at depth 1
        let deleted_operator = queries::get_deleted_operator_by_id(&conn, &operator.id)
            .unwrap()
            .unwrap();
        assert_eq!(deleted_operator.deleted_cascade_depth, Some(1), "Operator cascade depth should be 1 when deleted via user cascade");

        // Org member at depth 1
        let deleted_member = queries::get_deleted_org_member_by_id(&conn, &member.id)
            .unwrap()
            .unwrap();
        assert_eq!(deleted_member.deleted_cascade_depth, Some(1), "Org member cascade depth should be 1 when deleted via user cascade");
    }

    /// Cascade from org sets correct depths down the hierarchy.
    #[test]
    fn test_org_cascade_depths() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let (_user, member, _api_key) =
            create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

        // Org at depth 0
        assert_eq!(
            queries::get_deleted_organization_by_id(&conn, &org.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(0),
            "Directly deleted organization should have cascade depth 0"
        );

        // Org member at depth 1
        assert_eq!(
            queries::get_deleted_org_member_by_id(&conn, &member.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(1),
            "Org member cascade depth should be 1 when deleted via org cascade"
        );

        // Project at depth 1
        assert_eq!(
            queries::get_deleted_project_by_id(&conn, &project.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(1),
            "Project cascade depth should be 1 when deleted via org cascade"
        );

        // Product at depth 2
        assert_eq!(
            queries::get_deleted_product_by_id(&conn, &product.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(2),
            "Product cascade depth should be 2 when deleted via org->project cascade"
        );

        // License at depth 3
        assert_eq!(
            queries::get_deleted_license_by_id(&conn, &license.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(3),
            "License cascade depth should be 3 when deleted via org->project->product cascade"
        );
    }

    /// Cascade from project sets correct depths.
    #[test]
    fn test_project_cascade_depths() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        queries::soft_delete_project(&conn, &project.id).expect("Soft delete failed");

        // Project at depth 0
        assert_eq!(
            queries::get_deleted_project_by_id(&conn, &project.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(0),
            "Directly deleted project should have cascade depth 0"
        );

        // Product at depth 1
        assert_eq!(
            queries::get_deleted_product_by_id(&conn, &product.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(1),
            "Product cascade depth should be 1 when deleted via project cascade"
        );

        // License at depth 2
        assert_eq!(
            queries::get_deleted_license_by_id(&conn, &license.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(2),
            "License cascade depth should be 2 when deleted via project->product cascade"
        );
    }

    /// Cascade from product sets correct depth for license.
    #[test]
    fn test_product_cascade_depth() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        let license =
            create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(LICENSE_VALID_DAYS)));

        queries::soft_delete_product(&conn, &product.id).expect("Soft delete failed");

        // Product at depth 0
        assert_eq!(
            queries::get_deleted_product_by_id(&conn, &product.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(0),
            "Directly deleted product should have cascade depth 0"
        );

        // License at depth 1
        assert_eq!(
            queries::get_deleted_license_by_id(&conn, &license.id)
                .unwrap()
                .unwrap()
                .deleted_cascade_depth,
            Some(1),
            "License cascade depth should be 1 when deleted via product cascade"
        );
    }
}
