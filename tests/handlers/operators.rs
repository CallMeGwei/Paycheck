//! Integration tests for operator API handlers.
//!
//! These tests verify the business logic and response formats for operator-level
//! API endpoints, complementing the authorization tests in auth.rs.

use axum::{Router, body::Body, http::Request};
use serde_json::{Value, json};
use tower::ServiceExt;

#[path = "../common/mod.rs"]
mod common;
use common::{
    ONE_MONTH, create_test_operator, create_test_org, create_test_user, queries,
    setup_lemonsqueezy_config, setup_stripe_config, test_master_key,
};

use paycheck::db::AppState;
use paycheck::handlers;
use paycheck::models::OperatorRole;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

// ============================================================================
// Test App Setup
// ============================================================================

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
        audit_log_enabled: true, // Enable for audit log tests
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
// OPERATOR CRUD TESTS
// ============================================================================

mod operator_tests {
    use super::*;

    #[tokio::test]
    async fn test_create_operator_returns_operator() {
        let (app, state) = operator_app();

        let api_key: String;
        let new_user_id: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);
            api_key = key;

            // Create a user first, then use their ID to create an operator
            let new_user = create_test_user(&mut conn, "newoperator@test.com", "New Operator");
            new_user_id = new_user.id.clone();
        }

        let body = json!({
            "user_id": new_user_id,
            "role": "admin"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Create operator should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Response is now a User object with operator_role set
        // No api_key is auto-created (use Console or create one separately)
        assert_eq!(
            json["id"], new_user_id,
            "Response should include user id"
        );
        assert_eq!(
            json["operator_role"], "admin",
            "User should have the requested admin operator_role"
        );
    }

    #[tokio::test]
    async fn test_list_operators_returns_all_operators() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);
            let _ = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            let _ = create_test_operator(&mut conn, "view@test.com", OperatorRole::View);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "List operators should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let operators = json["items"].as_array().unwrap();
        assert_eq!(operators.len(), 3, "Should return all 3 created operators");
        assert_eq!(json["total"], 3, "Total count should be 3");
    }

    #[tokio::test]
    async fn test_get_operator_returns_operator_details() {
        let (app, state) = operator_app();

        let target_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);
            let (target_user, _) =
                create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            target_user_id = target_user.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/operators/{}", target_user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Get operator should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["id"], target_user_id,
            "Response should include correct user id"
        );
        assert_eq!(
            json["email"], "admin@test.com",
            "Response should include user email"
        );
        assert_eq!(
            json["operator_role"], "admin",
            "Response should show user's admin operator_role"
        );
    }

    #[tokio::test]
    async fn test_get_nonexistent_operator_returns_not_found() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/nonexistent-id")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "Nonexistent operator should return 404 Not Found"
        );
    }

    #[tokio::test]
    async fn test_update_operator_changes_role() {
        let (app, state) = operator_app();

        let target_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);
            let (target_user, _) =
                create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            target_user_id = target_user.id;
            api_key = key;
        }

        // UpdateOperator only has role field now (name is on User)
        let body = json!({
            "role": "view"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/operators/{}", target_user_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Update operator should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["operator_role"], "view",
            "User's operator_role should be updated to view"
        );
    }

    #[tokio::test]
    async fn test_update_operator_cannot_change_own_role() {
        let (app, state) = operator_app();

        let owner_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (owner_user, key) =
                create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);
            owner_user_id = owner_user.id;
            api_key = key;
        }

        // Try to change own role (should fail)
        let body = json!({
            "role": "view"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/operators/{}", owner_user_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "Changing own role should return 400 Bad Request"
        );
    }

    #[tokio::test]
    async fn test_delete_operator_removes_operator() {
        let (app, state) = operator_app();

        let target_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);
            let (target_user, _) =
                create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            target_user_id = target_user.id.clone();
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/operators/{}", target_user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Delete operator should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["success"], true,
            "Response should indicate deletion success"
        );

        // Verify operator role is revoked
        let mut conn = state.db.get().unwrap();
        let user = queries::get_user_by_id(&mut conn, &target_user_id)
            .unwrap()
            .expect("User should still exist");
        assert!(
            user.operator_role.is_none(),
            "Operator role should be revoked after deletion"
        );
    }

    #[tokio::test]
    async fn test_delete_operator_cannot_delete_self() {
        let (app, state) = operator_app();

        let owner_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (owner_user, key) =
                create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);
            owner_user_id = owner_user.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/operators/{}", owner_user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "Deleting self should return 400 Bad Request"
        );
    }

    #[tokio::test]
    async fn test_delete_nonexistent_operator_returns_not_found() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/operators/nonexistent-id")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "Deleting nonexistent operator should return 404 Not Found"
        );
    }
}

// ============================================================================
// ORGANIZATION CRUD TESTS
// ============================================================================

mod organization_tests {
    use super::*;

    #[tokio::test]
    async fn test_create_organization_without_owner() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
        }

        let body = json!({
            "name": "Acme Corp"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators/organizations")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Create organization should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(
            json["id"].as_str().is_some(),
            "Response should include organization id"
        );
        assert_eq!(
            json["name"], "Acme Corp",
            "Organization name should match request"
        );
        // No owner when owner_email not specified
        assert!(
            json["owner"].is_null() || json.get("owner").is_none(),
            "Owner should be null when owner_user_id not specified"
        );
    }

    #[tokio::test]
    async fn test_create_organization_with_owner() {
        let (app, state) = operator_app();

        let api_key: String;
        let owner_user_id: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;

            // Create a user first to use as owner
            let owner_user = create_test_user(&mut conn, "owner@acme.com", "John Owner");
            owner_user_id = owner_user.id.clone();
        }

        let body = json!({
            "name": "Acme Corp",
            "owner_user_id": owner_user_id
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators/organizations")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Create organization with owner should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(
            json["id"].as_str().is_some(),
            "Response should include organization id"
        );
        assert_eq!(
            json["name"], "Acme Corp",
            "Organization name should match request"
        );
        // OrganizationPublic doesn't include owner member - verify via database

        // Verify org member was created with full user details
        let mut conn = state.db.get().unwrap();
        let org_id = json["id"].as_str().unwrap();
        let members = queries::list_org_members_with_user(&mut conn, org_id).unwrap();
        assert_eq!(
            members.len(),
            1,
            "Organization should have exactly one member"
        );
        assert_eq!(
            members[0].email, "owner@acme.com",
            "Owner member email should match"
        );
        assert_eq!(
            members[0].role,
            paycheck::models::OrgMemberRole::Owner,
            "Member should have owner role"
        );
    }

    #[tokio::test]
    async fn test_list_organizations_returns_all_orgs() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            let _ = create_test_org(&mut conn, "Org 1");
            let _ = create_test_org(&mut conn, "Org 2");
            let _ = create_test_org(&mut conn, "Org 3");
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/organizations")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "List organizations should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let orgs = json["items"].as_array().unwrap();
        assert_eq!(orgs.len(), 3, "Should return all 3 created organizations");
        assert_eq!(json["total"], 3, "Total count should be 3");
    }

    #[tokio::test]
    async fn test_get_organization_returns_org_details() {
        let (app, state) = operator_app();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&mut conn, "Test Org");
            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/operators/organizations/{}", org_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Get organization should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["id"], org_id, "Response should include correct org id");
        assert_eq!(
            json["name"], "Test Org",
            "Response should include correct org name"
        );
    }

    #[tokio::test]
    async fn test_get_nonexistent_organization_returns_not_found() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/organizations/nonexistent-id")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "Nonexistent organization should return 404 Not Found"
        );
    }

    #[tokio::test]
    async fn test_update_organization_name() {
        let (app, state) = operator_app();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&mut conn, "Original Name");
            org_id = org.id;
            api_key = key;
        }

        let body = json!({
            "name": "Updated Name"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/operators/organizations/{}", org_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Update organization name should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["name"], "Updated Name",
            "Organization name should be updated"
        );
    }

    #[tokio::test]
    async fn test_update_organization_with_stripe_config() {
        let (app, state) = operator_app();
        let master_key = test_master_key();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&mut conn, "Test Org");
            org_id = org.id;
            api_key = key;
        }

        let body = json!({
            "stripe_config": {
                "secret_key": "sk_test_123",
                "publishable_key": "pk_test_123",
                "webhook_secret": "whsec_123"
            }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/operators/organizations/{}", org_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Update organization with Stripe config should return 200 OK"
        );

        // Verify config was encrypted and stored
        let mut conn = state.db.get().unwrap();
        let org = queries::get_organization_by_id(&mut conn, &org_id)
            .unwrap()
            .unwrap();
        let stripe_config = org.decrypt_stripe_config(&master_key).unwrap();
        assert!(
            stripe_config.is_some(),
            "Stripe config should be stored and decryptable"
        );
        let config = stripe_config.unwrap();
        assert_eq!(
            config.secret_key, "sk_test_123",
            "Stripe secret key should match submitted value"
        );
    }

    #[tokio::test]
    async fn test_update_organization_with_payment_provider() {
        let (app, state) = operator_app();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&mut conn, "Test Org");
            org_id = org.id;
            api_key = key;
        }

        let body = json!({
            "payment_provider": "stripe"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/operators/organizations/{}", org_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Update organization with payment provider should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["payment_provider"], "stripe",
            "Payment provider should be updated to stripe"
        );
    }

    #[tokio::test]
    async fn test_delete_organization_removes_org() {
        let (app, state) = operator_app();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&mut conn, "Test Org");
            org_id = org.id.clone();
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/operators/organizations/{}", org_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Delete organization should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["success"], true,
            "Response should indicate deletion success"
        );

        // Verify org is removed
        let mut conn = state.db.get().unwrap();
        let result = queries::get_organization_by_id(&mut conn, &org_id).unwrap();
        assert!(
            result.is_none(),
            "Organization should no longer exist after deletion"
        );
    }

    #[tokio::test]
    async fn test_delete_nonexistent_organization_returns_not_found() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/operators/organizations/nonexistent-id")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "Deleting nonexistent organization should return 404 Not Found"
        );
    }
}

// ============================================================================
// PAYMENT CONFIG SUPPORT TESTS
// ============================================================================

mod payment_config_tests {
    use super::*;

    #[tokio::test]
    async fn test_get_org_payment_config_returns_decrypted_stripe() {
        let (app, state) = operator_app();
        let master_key = test_master_key();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&mut conn, "Test Org");
            setup_stripe_config(&mut conn, &org.id, &master_key);
            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/operators/organizations/{}/payment-config",
                        org_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Get org payment config should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["org_id"], org_id,
            "Response should include correct org_id"
        );
        assert_eq!(
            json["org_name"], "Test Org",
            "Response should include correct org_name"
        );
        // Stripe config should be decrypted
        assert!(
            json["stripe_config"].is_object(),
            "Stripe config should be present as object"
        );
        assert_eq!(
            json["stripe_config"]["secret_key"], "sk_test_xxx",
            "Stripe secret key should be decrypted"
        );
        assert_eq!(
            json["stripe_config"]["webhook_secret"], "whsec_test_secret",
            "Stripe webhook secret should be decrypted"
        );
    }

    #[tokio::test]
    async fn test_get_org_payment_config_returns_decrypted_lemonsqueezy() {
        let (app, state) = operator_app();
        let master_key = test_master_key();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&mut conn, "Test Org");
            setup_lemonsqueezy_config(&mut conn, &org.id, &master_key);
            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/operators/organizations/{}/payment-config",
                        org_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Get org payment config with LemonSqueezy should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["org_id"], org_id,
            "Response should include correct org_id"
        );
        // LemonSqueezy config should be decrypted
        assert!(
            json["ls_config"].is_object(),
            "LemonSqueezy config should be present as object"
        );
        assert_eq!(
            json["ls_config"]["api_key"], "lskey_test_xxx",
            "LemonSqueezy API key should be decrypted"
        );
        assert_eq!(
            json["ls_config"]["webhook_secret"], "ls_test_secret",
            "LemonSqueezy webhook secret should be decrypted"
        );
    }

    #[tokio::test]
    async fn test_get_org_payment_config_no_configs_returns_null() {
        let (app, state) = operator_app();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&mut conn, "Test Org");
            // No payment config setup
            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/operators/organizations/{}/payment-config",
                        org_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Get org payment config with no configs should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(
            json["stripe_config"].is_null(),
            "Stripe config should be null when not configured"
        );
        assert!(
            json["ls_config"].is_null(),
            "LemonSqueezy config should be null when not configured"
        );
    }

    #[tokio::test]
    async fn test_get_org_payment_config_nonexistent_org_returns_not_found() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/organizations/nonexistent-id/payment-config")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "Payment config for nonexistent org should return 404 Not Found"
        );
    }
}

// ============================================================================
// AUDIT LOG QUERY TESTS
// ============================================================================

mod audit_log_tests {
    use super::*;

    #[tokio::test]
    async fn test_query_audit_logs_returns_logs() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "view@test.com", OperatorRole::View);
            api_key = key;
        }

        // Create an org to generate an audit log entry
        {
            let mut conn = state.db.get().unwrap();
            let (_, admin_key) =
                create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);

            // Use the API to create an org (this generates audit log)
            let app2 = handlers::operators::router(state.clone()).with_state(state.clone());
            let body = json!({"name": "Audit Test Org"});
            let _response = app2
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/operators/organizations")
                        .header("content-type", "application/json")
                        .header("Authorization", format!("Bearer {}", admin_key))
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Query audit logs should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Response is now paginated: { items: [...], total, limit, offset }
        let logs = json["items"].as_array().unwrap();
        assert!(!logs.is_empty(), "Should have at least one audit log entry");
        assert!(
            json["total"].as_i64().unwrap() >= 1,
            "Total count should be at least 1"
        );
    }

    #[tokio::test]
    async fn test_query_audit_logs_with_action_filter() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "view@test.com", OperatorRole::View);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs?action=create_org")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Query audit logs with action filter should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Response is now paginated: { items: [...], total, limit, offset }
        assert!(
            json["items"].is_array(),
            "Response items should be an array"
        );
    }

    #[tokio::test]
    async fn test_query_audit_logs_with_pagination() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "view@test.com", OperatorRole::View);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs?limit=10&offset=0")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Query audit logs with pagination should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Response is now paginated: { items: [...], total, limit, offset }
        let logs = json["items"].as_array().unwrap();
        assert!(logs.len() <= 10, "Result count should respect limit of 10");
        assert_eq!(
            json["limit"].as_i64().unwrap(),
            10,
            "Response should reflect requested limit"
        );
        assert_eq!(
            json["offset"].as_i64().unwrap(),
            0,
            "Response should reflect requested offset"
        );
    }

    #[tokio::test]
    async fn test_query_audit_logs_text_returns_plain_text() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "view@test.com", OperatorRole::View);
            api_key = key;
        }

        // Create an org to generate an audit log entry
        {
            let mut conn = state.db.get().unwrap();
            let (_, admin_key) =
                create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);

            let app2 = handlers::operators::router(state.clone()).with_state(state.clone());
            let body = json!({"name": "Text Test Org"});
            let _response = app2
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/operators/organizations")
                        .header("content-type", "application/json")
                        .header("Authorization", format!("Bearer {}", admin_key))
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs/text")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Query audit logs text should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();

        // Should have at least one line with create_org action
        assert!(!text.is_empty(), "Should have audit log content");
        assert!(
            text.contains("created org"),
            "Text output should contain the org creation action"
        );
        assert!(
            text.contains("Operator"),
            "Text output should contain actor type"
        );
    }

    #[tokio::test]
    async fn test_query_audit_logs_text_with_filters() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "view@test.com", OperatorRole::View);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs/text?action=create_org&limit=5")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Query audit logs text with filters should return 200 OK"
        );
    }

    // ========================================================================
    // PAGINATION EDGE CASE TESTS
    // ========================================================================

    /// Test pagination with offset beyond total results.
    /// Should return empty items but still show correct total count.
    #[tokio::test]
    async fn test_audit_log_offset_beyond_total() {
        let (app, state) = operator_app();

        let api_key: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
        }

        // Query with offset=1000 (way beyond any existing logs)
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs?offset=1000&limit=10")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Offset beyond total should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            json["items"].as_array().unwrap().is_empty(),
            "Items should be empty when offset exceeds total"
        );
        assert!(
            json["total"].as_i64().unwrap() >= 0,
            "Total count should still be reported"
        );
        assert_eq!(
            json["offset"].as_i64().unwrap(),
            1000,
            "Offset should reflect requested value"
        );
    }

    /// Test pagination with limit=0.
    /// The pagination layer clamps this to 1, so it should return at least 1 item.
    #[tokio::test]
    async fn test_audit_log_limit_zero() {
        let (app, state) = operator_app();

        let api_key: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            // Create some audit logs by creating an org
            let _ = create_test_org(&mut conn, "Test Org");
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs?limit=0")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "limit=0 should return 200 OK (clamped to 1)"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Limit=0 is clamped to 1 by pagination.rs
        assert_eq!(
            json["limit"].as_i64().unwrap(),
            1,
            "Limit should be clamped to minimum of 1"
        );
    }

    /// Test pagination with negative offset.
    /// The pagination layer treats this as 0.
    #[tokio::test]
    async fn test_audit_log_negative_offset() {
        let (app, state) = operator_app();

        let api_key: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs?offset=-5")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Negative offset should return 200 OK (treated as 0)"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Negative offset is treated as 0 by pagination.rs
        assert_eq!(
            json["offset"].as_i64().unwrap(),
            0,
            "Negative offset should be treated as 0"
        );
    }

    /// Test pagination limit is capped at 100.
    /// Requesting limit=1000 should return at most 100 entries.
    #[tokio::test]
    async fn test_audit_log_limit_capped() {
        let (app, state) = operator_app();

        let api_key: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs?limit=1000")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Very large limit should return 200 OK (capped at 100)"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Limit is capped at 100 by pagination.rs
        assert_eq!(
            json["limit"].as_i64().unwrap(),
            100,
            "Limit should be capped at maximum of 100"
        );
    }
}

// ============================================================================
// USER CRUD TESTS
// ============================================================================

mod user_tests {
    use super::*;

    #[tokio::test]
    async fn test_create_user_returns_user_with_roles() {
        let (app, state) = operator_app();

        let api_key: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
        }

        let body = json!({
            "email": "newuser@example.com",
            "name": "New User"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators/users")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Create user should return 200 OK");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["email"], "newuser@example.com",
            "Response should include user email"
        );
        assert_eq!(
            json["name"], "New User",
            "Response should include user name"
        );
        assert!(json["id"].is_string(), "Response should include user id");
        // New user should have empty roles
        assert!(
            json["operator"].is_null(),
            "New user should not have operator role"
        );
        assert!(
            json["memberships"].as_array().unwrap().is_empty(),
            "New user should have no org memberships"
        );
    }

    #[tokio::test]
    async fn test_create_user_duplicate_email_returns_error() {
        let (app, state) = operator_app();

        let api_key: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            // Create existing user
            create_test_user(&mut conn, "existing@example.com", "Existing User");
        }

        let body = json!({
            "email": "existing@example.com",
            "name": "Another User"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators/users")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            400,
            "Duplicate email should return 400 Bad Request"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["details"].as_str().unwrap().contains("already exists"),
            "Error message should indicate email already exists"
        );
    }

    #[tokio::test]
    async fn test_list_users_returns_paginated_users() {
        let (app, state) = operator_app();

        let api_key: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            // Create additional users
            create_test_user(&mut conn, "user1@example.com", "User One");
            create_test_user(&mut conn, "user2@example.com", "User Two");
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/users")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "List users should return 200 OK");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Should have at least 3 users (admin + 2 created)
        assert!(
            json["total"].as_i64().unwrap() >= 3,
            "Total should be at least 3 (admin + 2 created users)"
        );
        assert!(
            json["items"].as_array().unwrap().len() >= 3,
            "Items should contain at least 3 users"
        );
    }

    #[tokio::test]
    async fn test_list_users_filter_by_email() {
        let (app, state) = operator_app();

        let api_key: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            create_test_user(&mut conn, "findme@example.com", "Find Me");
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/users?email=findme@example.com")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "List users with email filter should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["total"], 1,
            "Filter should return exactly one matching user"
        );
        assert_eq!(
            json["items"][0]["email"], "findme@example.com",
            "Filtered user should match the email query"
        );
    }

    #[tokio::test]
    async fn test_get_user_returns_user_with_roles() {
        let (app, state) = operator_app();

        let api_key: String;
        let user_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            let user = create_test_user(&mut conn, "target@example.com", "Target User");
            user_id = user.id;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/operators/users/{}", user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Get user should return 200 OK");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["email"], "target@example.com",
            "Response should include user email"
        );
        assert_eq!(
            json["name"], "Target User",
            "Response should include user name"
        );
    }

    #[tokio::test]
    async fn test_get_user_not_found_returns_404() {
        let (app, state) = operator_app();

        let api_key: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/users/nonexistent-id")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            404,
            "Nonexistent user should return 404 Not Found"
        );
    }

    #[tokio::test]
    async fn test_update_user_changes_fields() {
        let (app, state) = operator_app();

        let api_key: String;
        let user_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            let user = create_test_user(&mut conn, "update@example.com", "Old Name");
            user_id = user.id;
        }

        let body = json!({
            "name": "New Name"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&format!("/operators/users/{}", user_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Update user should return 200 OK");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["name"], "New Name", "User name should be updated");
        assert_eq!(
            json["email"], "update@example.com",
            "User email should remain unchanged"
        );
    }

    #[tokio::test]
    async fn test_update_user_email_conflict_returns_error() {
        let (app, state) = operator_app();

        let api_key: String;
        let user_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            let user = create_test_user(&mut conn, "original@example.com", "Original");
            user_id = user.id;
            create_test_user(&mut conn, "taken@example.com", "Taken");
        }

        let body = json!({
            "email": "taken@example.com"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&format!("/operators/users/{}", user_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            400,
            "Email conflict should return 400 Bad Request"
        );
    }

    #[tokio::test]
    async fn test_delete_user_soft_deletes() {
        let (app, state) = operator_app();

        let api_key: String;
        let user_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            let user = create_test_user(&mut conn, "delete@example.com", "Delete Me");
            user_id = user.id;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/operators/users/{}", user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Delete user should return 200 OK");

        // Verify user is soft-deleted (not found via normal query)
        let mut conn = state.db.get().unwrap();
        let user = queries::get_user_by_id(&mut conn, &user_id).unwrap();
        assert!(
            user.is_none(),
            "User should not be found via normal query after soft delete"
        );

        // But still exists as deleted
        let deleted = queries::get_deleted_user_by_id(&mut conn, &user_id).unwrap();
        assert!(
            deleted.is_some(),
            "User should still exist in deleted state"
        );
    }

    #[tokio::test]
    async fn test_delete_user_cannot_delete_self() {
        let (app, state) = operator_app();

        let api_key: String;
        let admin_user_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (user, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            admin_user_id = user.id;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/operators/users/{}", admin_user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            400,
            "Deleting self should return 400 Bad Request"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["details"].as_str().unwrap().contains("yourself"),
            "Error message should indicate cannot delete self"
        );
    }

    #[tokio::test]
    async fn test_restore_user_restores_soft_deleted() {
        let (app, state) = operator_app();

        let api_key: String;
        let user_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            let user = create_test_user(&mut conn, "restore@example.com", "Restore Me");
            user_id = user.id.clone();
            queries::soft_delete_user(&mut conn, &user.id).unwrap();
        }

        let body = json!({ "force": false });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/operators/users/{}/restore", user_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Restore user should return 200 OK");

        // Verify user is restored
        let mut conn = state.db.get().unwrap();
        let user = queries::get_user_by_id(&mut conn, &user_id).unwrap();
        assert!(
            user.is_some(),
            "User should be found via normal query after restoration"
        );
    }

    #[tokio::test]
    async fn test_hard_delete_user_permanently_removes() {
        let (app, state) = operator_app();

        let api_key: String;
        let user_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            let user = create_test_user(&mut conn, "gdpr@example.com", "GDPR Delete");
            user_id = user.id;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/operators/users/{}/hard-delete", user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Hard delete user should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["permanently_deleted"], true,
            "Response should indicate permanent deletion"
        );

        // Verify user is completely gone
        let mut conn = state.db.get().unwrap();
        let user = queries::get_user_by_id(&mut conn, &user_id).unwrap();
        assert!(
            user.is_none(),
            "User should not be found via normal query after hard delete"
        );
        let deleted = queries::get_deleted_user_by_id(&mut conn, &user_id).unwrap();
        assert!(
            deleted.is_none(),
            "User should not be found even in deleted state after hard delete"
        );
    }

    #[tokio::test]
    async fn test_hard_delete_user_cannot_delete_self() {
        let (app, state) = operator_app();

        let api_key: String;
        let admin_user_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (user, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            admin_user_id = user.id;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/operators/users/{}/hard-delete", admin_user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            400,
            "Hard deleting self should return 400 Bad Request"
        );
    }
}

// ============================================================================
// OPERATOR API KEY TESTS
// ============================================================================

mod operator_api_key_tests {
    use super::*;

    #[tokio::test]
    async fn test_create_api_key_for_user() {
        let (app, state) = operator_app();

        let api_key: String;
        let user_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            let user = create_test_user(&mut conn, "target@example.com", "Target User");
            user_id = user.id;
        }

        let body = json!({
            "name": "New API Key"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/operators/users/{}/api-keys", user_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Create API key should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["name"], "New API Key",
            "Response should include key name"
        );
        assert!(
            json["key"].as_str().unwrap().starts_with("pc_"),
            "API key should have 'pc_' prefix"
        );
        assert!(json["id"].is_string(), "Response should include key id");
        assert!(
            json["prefix"].is_string(),
            "Response should include key prefix"
        );
    }

    #[tokio::test]
    async fn test_create_api_key_with_expiration() {
        let (app, state) = operator_app();

        let api_key: String;
        let user_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            let user = create_test_user(&mut conn, "target@example.com", "Target User");
            user_id = user.id;
        }

        let body = json!({
            "name": "Expiring Key",
            "expires_in_days": ONE_MONTH
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/operators/users/{}/api-keys", user_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Create API key with expiration should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(
            json["expires_at"].is_number(),
            "Response should include expires_at timestamp"
        );
    }

    #[tokio::test]
    async fn test_create_api_key_user_not_found() {
        let (app, state) = operator_app();

        let api_key: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
        }

        let body = json!({
            "name": "Key for Nonexistent"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators/users/nonexistent-id/api-keys")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            404,
            "Creating API key for nonexistent user should return 404 Not Found"
        );
    }

    #[tokio::test]
    async fn test_list_api_keys_returns_user_keys() {
        let (app, state) = operator_app();

        let api_key: String;
        let user_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            let user = create_test_user(&mut conn, "target@example.com", "Target User");
            user_id = user.id.clone();
            // Create some API keys for this user
            queries::create_api_key(&mut conn, &user.id, "Key 1", None, true, None).unwrap();
            queries::create_api_key(&mut conn, &user.id, "Key 2", None, true, None).unwrap();
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/operators/users/{}/api-keys", user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "List API keys should return 200 OK");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["total"], 2,
            "Total should reflect the 2 created API keys"
        );
        assert_eq!(
            json["items"].as_array().unwrap().len(),
            2,
            "Items should contain 2 API keys"
        );
    }

    #[tokio::test]
    async fn test_revoke_api_key_removes_key() {
        let (app, state) = operator_app();

        let api_key: String;
        let user_id: String;
        let key_to_revoke_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            let user = create_test_user(&mut conn, "target@example.com", "Target User");
            user_id = user.id.clone();
            let (key_record, _) =
                queries::create_api_key(&mut conn, &user.id, "To Revoke", None, true, None).unwrap();
            key_to_revoke_id = key_record.id;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!(
                        "/operators/users/{}/api-keys/{}",
                        user_id, key_to_revoke_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Revoke API key should return 200 OK"
        );

        // Verify key has revoked_at set
        let mut conn = state.db.get().unwrap();
        let key = queries::get_api_key_by_id(&mut conn, &key_to_revoke_id)
            .unwrap()
            .expect("Key should still exist in DB");
        assert!(
            key.revoked_at.is_some(),
            "Key should have revoked_at timestamp set"
        );
    }

    #[tokio::test]
    async fn test_revoke_api_key_wrong_user_returns_not_found() {
        let (app, state) = operator_app();

        let api_key: String;
        let other_user_id: String;
        let key_id: String;
        {
            let mut conn = state.db.get().unwrap();
            let (_, key) = create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;
            let user = create_test_user(&mut conn, "owner@example.com", "Key Owner");
            let other_user = create_test_user(&mut conn, "other@example.com", "Other User");
            other_user_id = other_user.id;
            let (key_record, _) =
                queries::create_api_key(&mut conn, &user.id, "Owned Key", None, true, None).unwrap();
            key_id = key_record.id;
        }

        // Try to revoke the key via wrong user's path
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!(
                        "/operators/users/{}/api-keys/{}",
                        other_user_id, key_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            404,
            "Revoking API key via wrong user path should return 404 Not Found"
        );
    }
}
