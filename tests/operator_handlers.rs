//! Integration tests for operator API handlers.
//!
//! These tests verify the business logic and response formats for operator-level
//! API endpoints, complementing the authorization tests in auth.rs.

use axum::{Router, body::Body, http::Request};
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::*;

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
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: std::sync::Arc::new(
            paycheck::rate_limit::ActivationRateLimiter::default(),
        ),
        email_service: std::sync::Arc::new(paycheck::email::EmailService::new(None, "test@example.com".to_string())),
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
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);
            api_key = key;

            // Create a user first, then use their ID to create an operator
            let new_user = create_test_user(&conn, "newoperator@test.com", "New Operator");
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Response is now a flat Operator: { id, user_id, role, created_at }
        // No api_key is auto-created (use Console or create one separately)
        assert!(json["id"].as_str().is_some());
        assert_eq!(json["user_id"], new_user_id);
        assert_eq!(json["role"], "admin");
    }

    #[tokio::test]
    async fn test_list_operators_returns_all_operators() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);
            let _ = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            let _ = create_test_operator(&conn, "view@test.com", OperatorRole::View);
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let operators = json["items"].as_array().unwrap();
        assert_eq!(operators.len(), 3);
        assert_eq!(json["total"], 3);
    }

    #[tokio::test]
    async fn test_get_operator_returns_operator_details() {
        let (app, state) = operator_app();

        let target_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);
            let (_, target, _) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            target_id = target.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/operators/{}", target_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["id"], target_id);
        assert_eq!(json["email"], "admin@test.com");
        assert_eq!(json["role"], "admin");
    }

    #[tokio::test]
    async fn test_get_nonexistent_operator_returns_not_found() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);
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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_operator_changes_role() {
        let (app, state) = operator_app();

        let target_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);
            let (_, target, _) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            target_id = target.id;
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
                    .uri(format!("/operators/{}", target_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["role"], "view");
    }

    #[tokio::test]
    async fn test_update_operator_cannot_change_own_role() {
        let (app, state) = operator_app();

        let owner_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, owner, key) = create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);
            owner_id = owner.id;
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
                    .uri(format!("/operators/{}", owner_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_operator_removes_operator() {
        let (app, state) = operator_app();

        let target_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);
            let (_, target, _) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            target_id = target.id.clone();
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/operators/{}", target_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);

        // Verify operator is removed
        let conn = state.db.get().unwrap();
        let result = queries::get_operator_by_id(&conn, &target_id).unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_operator_cannot_delete_self() {
        let (app, state) = operator_app();

        let owner_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, owner, key) = create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);
            owner_id = owner.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/operators/{}", owner_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_nonexistent_operator_returns_not_found() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "owner@test.com", OperatorRole::Owner);
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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
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
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["organization"]["id"].as_str().is_some());
        assert_eq!(json["organization"]["name"], "Acme Corp");
        // No owner when owner_email not specified
        assert!(json["owner"].is_null() || json.get("owner").is_none());
    }

    #[tokio::test]
    async fn test_create_organization_with_owner() {
        let (app, state) = operator_app();

        let api_key: String;
        let owner_user_id: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            api_key = key;

            // Create a user first to use as owner
            let owner_user = create_test_user(&conn, "owner@acme.com", "John Owner");
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["organization"]["id"].as_str().is_some());
        assert_eq!(json["organization"]["name"], "Acme Corp");
        // Owner member should be returned (OrgMember struct: id, user_id, org_id, role)
        // No email in response - OrgMember doesn't have user details, use query below
        assert!(json["owner"]["id"].as_str().is_some());
        assert_eq!(json["owner"]["user_id"], owner_user_id);
        assert_eq!(json["owner"]["role"], "owner");

        // Verify org member was created with full user details
        let conn = state.db.get().unwrap();
        let org_id = json["organization"]["id"].as_str().unwrap();
        let members = queries::list_org_members_with_user(&conn, org_id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].email, "owner@acme.com");
        assert_eq!(members[0].role, paycheck::models::OrgMemberRole::Owner);
    }

    #[tokio::test]
    async fn test_list_organizations_returns_all_orgs() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            let _ = create_test_org(&conn, "Org 1");
            let _ = create_test_org(&conn, "Org 2");
            let _ = create_test_org(&conn, "Org 3");
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let orgs = json["items"].as_array().unwrap();
        assert_eq!(orgs.len(), 3);
        assert_eq!(json["total"], 3);
    }

    #[tokio::test]
    async fn test_get_organization_returns_org_details() {
        let (app, state) = operator_app();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&conn, "Test Org");
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["id"], org_id);
        assert_eq!(json["name"], "Test Org");
    }

    #[tokio::test]
    async fn test_get_nonexistent_organization_returns_not_found() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_organization_name() {
        let (app, state) = operator_app();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&conn, "Original Name");
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["name"], "Updated Name");
    }

    #[tokio::test]
    async fn test_update_organization_with_stripe_config() {
        let (app, state) = operator_app();
        let master_key = test_master_key();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&conn, "Test Org");
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Verify config was encrypted and stored
        let conn = state.db.get().unwrap();
        let org = queries::get_organization_by_id(&conn, &org_id)
            .unwrap()
            .unwrap();
        let stripe_config = org.decrypt_stripe_config(&master_key).unwrap();
        assert!(stripe_config.is_some());
        let config = stripe_config.unwrap();
        assert_eq!(config.secret_key, "sk_test_123");
    }

    #[tokio::test]
    async fn test_update_organization_with_payment_provider() {
        let (app, state) = operator_app();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&conn, "Test Org");
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["payment_provider"], "stripe");
    }

    #[tokio::test]
    async fn test_delete_organization_removes_org() {
        let (app, state) = operator_app();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&conn, "Test Org");
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);

        // Verify org is removed
        let conn = state.db.get().unwrap();
        let result = queries::get_organization_by_id(&conn, &org_id).unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_organization_returns_not_found() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
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
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&conn, "Test Org");
            setup_stripe_config(&conn, &org.id, &master_key);
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["org_id"], org_id);
        assert_eq!(json["org_name"], "Test Org");
        // Stripe config should be decrypted
        assert!(json["stripe_config"].is_object());
        assert_eq!(json["stripe_config"]["secret_key"], "sk_test_xxx");
        assert_eq!(json["stripe_config"]["webhook_secret"], "whsec_test_secret");
    }

    #[tokio::test]
    async fn test_get_org_payment_config_returns_decrypted_lemonsqueezy() {
        let (app, state) = operator_app();
        let master_key = test_master_key();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&conn, "Test Org");
            setup_lemonsqueezy_config(&conn, &org.id, &master_key);
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["org_id"], org_id);
        // LemonSqueezy config should be decrypted
        assert!(json["ls_config"].is_object());
        assert_eq!(json["ls_config"]["api_key"], "lskey_test_xxx");
        assert_eq!(json["ls_config"]["webhook_secret"], "ls_test_secret");
    }

    #[tokio::test]
    async fn test_get_org_payment_config_no_configs_returns_null() {
        let (app, state) = operator_app();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
            let org = create_test_org(&conn, "Test Org");
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["stripe_config"].is_null());
        assert!(json["ls_config"].is_null());
    }

    #[tokio::test]
    async fn test_get_org_payment_config_nonexistent_org_returns_not_found() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);
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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
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
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "view@test.com", OperatorRole::View);
            api_key = key;
        }

        // Create an org to generate an audit log entry
        {
            let conn = state.db.get().unwrap();
            let (_, _, admin_key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Response is now paginated: { items: [...], total, limit, offset }
        let logs = json["items"].as_array().unwrap();
        assert!(!logs.is_empty(), "Should have at least one audit log entry");
        assert!(json["total"].as_i64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn test_query_audit_logs_with_action_filter() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "view@test.com", OperatorRole::View);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs?action=create_organization")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Response is now paginated: { items: [...], total, limit, offset }
        assert!(json["items"].is_array());
    }

    #[tokio::test]
    async fn test_query_audit_logs_with_pagination() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "view@test.com", OperatorRole::View);
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Response is now paginated: { items: [...], total, limit, offset }
        let logs = json["items"].as_array().unwrap();
        assert!(logs.len() <= 10, "Should respect limit");
        assert_eq!(json["limit"].as_i64().unwrap(), 10);
        assert_eq!(json["offset"].as_i64().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_query_audit_logs_text_returns_plain_text() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "view@test.com", OperatorRole::View);
            api_key = key;
        }

        // Create an org to generate an audit log entry
        {
            let conn = state.db.get().unwrap();
            let (_, _, admin_key) = create_test_operator(&conn, "admin@test.com", OperatorRole::Admin);

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();

        // Should have at least one line with create_organization action
        assert!(!text.is_empty(), "Should have audit log content");
        assert!(
            text.contains("created organization"),
            "Should contain the org creation action"
        );
        assert!(text.contains("Operator"), "Should contain actor type");
    }

    #[tokio::test]
    async fn test_query_audit_logs_text_with_filters() {
        let (app, state) = operator_app();

        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let (_, _, key) = create_test_operator(&conn, "view@test.com", OperatorRole::View);
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/operators/audit-logs/text?action=create_organization&limit=5")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
