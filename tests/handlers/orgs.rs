//! Integration tests for org API handlers.
//!
//! These tests verify the business logic and response formats for all org-level
//! API endpoints, complementing the authorization tests in auth.rs.

use axum::{Router, body::Body, http::Request};
use serde_json::{Value, json};
use tower::ServiceExt;

#[path = "../common/mod.rs"]
mod common;
use common::{ONE_MONTH, ONE_YEAR, *};

use paycheck::db::AppState;
use paycheck::handlers;
use paycheck::models::OrgMemberRole;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

// ============================================================================
// Test App Setup
// ============================================================================

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

// ============================================================================
// PRODUCT CRUD TESTS
// ============================================================================

mod product_tests {
    use super::*;

    #[tokio::test]
    async fn test_create_product_returns_full_product() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_user, _member, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        let body = json!({
            "name": "Pro Plan",
            "tier": "pro",
            "license_exp_days": ONE_YEAR,
            "updates_exp_days": 180,
            "activation_limit": 10,
            "device_limit": 5,
            "features": ["feature1", "feature2", "advanced"]
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

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "create product should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(
            json["id"].as_str().is_some(),
            "response should include product ID"
        );
        assert_eq!(json["name"], "Pro Plan", "product name should match input");
        assert_eq!(json["tier"], "pro", "product tier should match input");
        assert_eq!(
            json["license_exp_days"], ONE_YEAR,
            "license expiration should be one year"
        );
        assert_eq!(
            json["updates_exp_days"], 180,
            "updates expiration should be 180 days"
        );
        assert_eq!(
            json["activation_limit"], 10,
            "activation limit should match input"
        );
        assert_eq!(json["device_limit"], 5, "device limit should match input");
        assert_eq!(
            json["features"],
            json!(["feature1", "feature2", "advanced"]),
            "features array should match input"
        );
    }

    #[tokio::test]
    async fn test_list_products_returns_all_products() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

            // Create multiple products
            create_test_product(&mut conn, &project.id, "Free Plan", "free");
            create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
            create_test_product(&mut conn, &project.id, "Enterprise", "enterprise");

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}/products", org_id, project_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "list products should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let products = json["items"].as_array().unwrap();
        assert_eq!(products.len(), 3, "should return all 3 created products");
        assert_eq!(json["total"], 3, "total count should be 3");
    }

    #[tokio::test]
    async fn test_get_product_returns_product_details() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}",
                        org_id, project_id, product_id
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
            "get product should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["id"], product_id,
            "product ID should match requested ID"
        );
        assert_eq!(json["name"], "Pro Plan", "product name should match");
        assert_eq!(json["tier"], "pro", "product tier should match");
    }

    #[tokio::test]
    async fn test_update_product_changes_fields() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        let body = json!({
            "name": "Pro Plan Plus",
            "tier": "pro_plus",
            "device_limit": 10
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}",
                        org_id, project_id, product_id
                    ))
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
            "update product should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["name"], "Pro Plan Plus",
            "product name should be updated"
        );
        assert_eq!(json["tier"], "pro_plus", "product tier should be updated");
        assert_eq!(json["device_limit"], 10, "device limit should be updated");
    }

    /// Tests that nullable fields can be set to null via JSON using explicit null values.
    /// This verifies the double-Option deserialization pattern works through the HTTP layer.
    #[tokio::test]
    async fn test_update_product_nullable_fields_to_null() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            // Verify product has initial values
            assert!(product.price_cents.is_some(), "product should have price_cents initially");
            assert!(product.currency.is_some(), "product should have currency initially");
            assert!(product.device_limit.is_some(), "product should have device_limit initially");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        // Send JSON with explicit null values - this tests the double-Option deserialization
        let body = json!({
            "device_limit": null,
            "price_cents": null,
            "currency": null,
            "device_inactive_days": null
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}",
                        org_id, project_id, product_id
                    ))
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
            "update product should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Fields sent as null should now be null in the response
        assert!(
            json["device_limit"].is_null(),
            "device_limit should be null after explicit null update, got: {:?}",
            json["device_limit"]
        );
        assert!(
            json["price_cents"].is_null(),
            "price_cents should be null after explicit null update, got: {:?}",
            json["price_cents"]
        );
        assert!(
            json["currency"].is_null(),
            "currency should be null after explicit null update, got: {:?}",
            json["currency"]
        );
        assert!(
            json["device_inactive_days"].is_null(),
            "device_inactive_days should be null after explicit null update, got: {:?}",
            json["device_inactive_days"]
        );

        // Other fields should be unchanged
        assert_eq!(json["name"], "Pro Plan", "name should be unchanged");
        assert_eq!(json["tier"], "pro", "tier should be unchanged");
    }

    #[tokio::test]
    async fn test_delete_product_removes_product() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id.clone();
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}",
                        org_id, project_id, product_id
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
            "delete product should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["success"], true,
            "delete response should indicate success"
        );

        // Verify product is actually deleted
        let mut conn = state.db.get().unwrap();
        let result = queries::get_product_by_id(&mut conn, &product_id).unwrap();
        assert!(
            result.is_none(),
            "product should no longer exist in database"
        );
    }

    #[tokio::test]
    async fn test_get_product_wrong_project_returns_not_found() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project1_id: String;
        let project2_product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project1 = create_test_project(&mut conn, &org.id, "Project 1", &master_key);
            let project2 = create_test_project(&mut conn, &org.id, "Project 2", &master_key);
            let product2 = create_test_product(&mut conn, &project2.id, "Pro Plan", "pro");

            org_id = org.id;
            project1_id = project1.id;
            project2_product_id = product2.id;
            api_key = key;
        }

        // Try to get product from project2 via project1's URL
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}",
                        org_id, project1_id, project2_product_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "accessing product from wrong project should return 404"
        );
    }
}

// ============================================================================
// LICENSE MANAGEMENT TESTS
// ============================================================================

mod license_tests {
    use super::*;

    #[tokio::test]
    async fn test_create_single_license_returns_license_details() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        let body = json!({
            "product_id": product_id,
            "customer_id": "cust_12345"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/licenses", org_id, project_id))
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
            "create license should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let licenses = json["items"].as_array().unwrap();
        assert_eq!(licenses.len(), 1, "should create exactly one license");
        assert!(
            licenses[0]["id"].as_str().is_some(),
            "license should have an ID"
        );
        // Note: "key" field no longer exists (email-only activation model)
        assert!(
            licenses[0]["expires_at"].as_i64().is_some(),
            "license should have expiration date from product default"
        );
    }

    #[tokio::test]
    async fn test_create_bulk_licenses_with_count() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        let body = json!({
            "product_id": product_id,
            "count": 5,
            "email": "customer@example.com"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/licenses", org_id, project_id))
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
            "bulk create licenses should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let licenses = json["items"].as_array().unwrap();
        assert_eq!(
            licenses.len(),
            5,
            "should create exactly 5 licenses as requested"
        );

        // All IDs should be unique
        let ids: Vec<&str> = licenses.iter().map(|l| l["id"].as_str().unwrap()).collect();
        let unique_ids: std::collections::HashSet<&str> = ids.iter().cloned().collect();
        assert_eq!(
            ids.len(),
            unique_ids.len(),
            "all license IDs should be unique"
        );
    }

    #[tokio::test]
    async fn test_create_license_count_exceeds_limit_returns_error() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        let body = json!({
            "product_id": product_id,
            "count": 101  // Exceeds limit of 100
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/licenses", org_id, project_id))
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
            "exceeding bulk limit of 100 should return 400"
        );
    }

    #[tokio::test]
    async fn test_create_license_with_custom_expiration() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        // Override to one month expiration
        let body = json!({
            "product_id": product_id,
            "license_exp_days": ONE_MONTH,
            "updates_exp_days": 60,
            "email": "customer@example.com"
        });

        let before = now();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/licenses", org_id, project_id))
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
            "create license with custom expiration should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let licenses = json["items"].as_array().unwrap();
        let license_exp = licenses[0]["expires_at"].as_i64().unwrap();
        let updates_exp = licenses[0]["updates_expires_at"].as_i64().unwrap();

        // Should be ~30 days from now
        assert!(
            license_exp >= before + (ONE_MONTH * 86400) - 5,
            "license expiration should be at least 30 days from now"
        );
        assert!(
            license_exp <= before + (ONE_MONTH * 86400) + 5,
            "license expiration should be at most 30 days from now"
        );

        // Updates should be ~60 days from now
        assert!(
            updates_exp >= before + (60 * 86400) - 5,
            "updates expiration should be at least 60 days from now"
        );
        assert!(
            updates_exp <= before + (60 * 86400) + 5,
            "updates expiration should be at most 60 days from now"
        );
    }

    #[tokio::test]
    async fn test_create_perpetual_license_with_perpetual_product() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

            // Create a perpetual product (no expiration)
            let input = paycheck::models::CreateProduct {
                name: "Lifetime".to_string(),
                tier: "lifetime".to_string(),
                price_cents: None,
                currency: None,
                license_exp_days: None,
                updates_exp_days: None,
                activation_limit: Some(5),
                device_limit: Some(3),
        device_inactive_days: None,
                features: vec![],
            };
            let product = queries::create_product(&mut conn, &project.id, &input).unwrap();

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        // Don't specify any expiration override - use product defaults (which are perpetual)
        let body = json!({
            "product_id": product_id,
            "email": "customer@example.com"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/licenses", org_id, project_id))
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
            "create perpetual license should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let licenses = json["items"].as_array().unwrap();
        assert!(
            licenses[0]["expires_at"].is_null(),
            "perpetual license should have null expires_at"
        );
        assert!(
            licenses[0]["updates_expires_at"].is_null(),
            "perpetual license should have null updates_expires_at"
        );
    }

    #[tokio::test]
    async fn test_get_license_returns_license_with_devices() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let license_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
            let license = create_test_license(
                &conn,
                &project.id,
                &product.id,
                Some(future_timestamp(ONE_YEAR)),
            );

            // Create a device for the license
            create_test_device(&mut conn, &license.id, "device-1", DeviceType::Uuid);

            org_id = org.id;
            project_id = project.id;
            license_id = license.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}",
                        org_id, project_id, license_id
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
            "get license should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Verify license fields
        assert_eq!(
            json["id"], license_id,
            "license ID should match requested ID"
        );
        assert!(
            json["product_name"].as_str().is_some(),
            "license should include product name"
        );

        // Verify devices array
        let devices = json["devices"].as_array().unwrap();
        assert_eq!(devices.len(), 1, "license should have exactly one device");
        assert_eq!(
            devices[0]["device_id"], "device-1",
            "device ID should match"
        );
    }

    #[tokio::test]
    async fn test_revoke_license_marks_as_revoked() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let license_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
            let license = create_test_license(
                &conn,
                &project.id,
                &product.id,
                Some(future_timestamp(ONE_YEAR)),
            );

            org_id = org.id;
            project_id = project.id;
            license_id = license.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}/revoke",
                        org_id, project_id, license_id
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
            "revoke license should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["success"], true,
            "revoke response should indicate success"
        );

        // Verify in database
        let mut conn = state.db.get().unwrap();
        let license = queries::get_license_by_id(&mut conn, &license_id)
            .unwrap()
            .unwrap();
        assert!(
            license.revoked,
            "license should be marked as revoked in database"
        );
    }

    #[tokio::test]
    async fn test_revoke_already_revoked_returns_error() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let license_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
            let license = create_test_license(
                &conn,
                &project.id,
                &product.id,
                Some(future_timestamp(ONE_YEAR)),
            );

            // Pre-revoke the license
            queries::revoke_license(&mut conn, &license.id).unwrap();

            org_id = org.id;
            project_id = project.id;
            license_id = license.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}/revoke",
                        org_id, project_id, license_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "revoking already-revoked license should return 400"
        );
    }

    // NOTE: test_replace_license removed - license replacement endpoint no longer exists
    // (email-only activation model has no permanent license keys to replace)

    #[tokio::test]
    async fn test_deactivate_device_removes_device() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let license_id: String;
        let device_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
            let license = create_test_license(
                &conn,
                &project.id,
                &product.id,
                Some(future_timestamp(ONE_YEAR)),
            );

            // Create devices
            create_test_device(&mut conn, &license.id, "device-1", DeviceType::Uuid);
            create_test_device(&mut conn, &license.id, "device-2", DeviceType::Uuid);

            org_id = org.id;
            project_id = project.id;
            license_id = license.id.clone();
            device_id = "device-1".to_string();
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}/devices/{}",
                        org_id, project_id, license_id, device_id
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
            "deactivate device should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["deactivated"], true,
            "response should indicate device was deactivated"
        );
        assert_eq!(
            json["device_id"], device_id,
            "response should include deactivated device ID"
        );
        assert_eq!(
            json["remaining_devices"], 1,
            "remaining devices should be 1 after removing one of two"
        );

        // Verify device is removed from database
        let mut conn = state.db.get().unwrap();
        let devices = queries::list_devices_for_license(&mut conn, &license_id).unwrap();
        assert_eq!(
            devices.len(),
            1,
            "license should have 1 device remaining in database"
        );
        assert_eq!(
            devices[0].device_id, "device-2",
            "remaining device should be device-2"
        );
    }
}

// ============================================================================
// PROJECT CRUD TESTS
// ============================================================================

mod project_tests {
    use super::*;

    #[tokio::test]
    async fn test_create_project_returns_project_details() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

            org_id = org.id;
            api_key = key;
        }

        let body = json!({
            "name": "My New Project",
            "license_key_prefix": "MNP",
            "redirect_url": "https://myapp.com/activated"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects", org_id))
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
            "create project should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(
            json["id"].as_str().is_some(),
            "response should include project ID"
        );
        assert_eq!(
            json["name"], "My New Project",
            "project name should match input"
        );
        assert_eq!(
            json["license_key_prefix"], "MNP",
            "license key prefix should match input"
        );
        assert_eq!(
            json["redirect_url"], "https://myapp.com/activated",
            "redirect URL should match input"
        );
        // Public key should be present (for client-side JWT verification)
        assert!(
            json["public_key"].as_str().is_some(),
            "project should include public key for JWT verification"
        );
    }

    #[tokio::test]
    async fn test_list_projects_returns_all_org_projects() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

            // Create multiple projects
            create_test_project(&mut conn, &org.id, "Project 1", &master_key);
            create_test_project(&mut conn, &org.id, "Project 2", &master_key);
            create_test_project(&mut conn, &org.id, "Project 3", &master_key);

            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects", org_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "list projects should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let projects = json["items"].as_array().unwrap();
        assert_eq!(projects.len(), 3, "should return all 3 created projects");
        assert_eq!(json["total"], 3, "total count should be 3");
    }

    #[tokio::test]
    async fn test_update_project_changes_fields() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Original Name", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        let body = json!({
            "name": "Updated Name"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/orgs/{}/projects/{}", org_id, project_id))
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
            "update project should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["name"], "Updated Name",
            "project name should be updated"
        );
    }

    #[tokio::test]
    async fn test_get_project_returns_project_details() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "My Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org_id, project_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "get project should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["id"], project_id,
            "project ID should match requested ID"
        );
        assert_eq!(json["name"], "My Project", "project name should match");
        assert!(
            json["public_key"].as_str().is_some(),
            "project should include public key"
        );
    }

    #[tokio::test]
    async fn test_get_project_not_found_returns_error() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/nonexistent-project-id", org_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "nonexistent project should return 404"
        );
    }

    #[tokio::test]
    async fn test_get_project_cross_org_returns_not_found() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org1_id: String;
        let org2_project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org1 = create_test_org(&mut conn, "Org 1");
            let org2 = create_test_org(&mut conn, "Org 2");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org1.id, "admin@test.com", OrgMemberRole::Owner);
            let project2 = create_test_project(&mut conn, &org2.id, "Org2 Project", &master_key);

            org1_id = org1.id;
            org2_project_id = project2.id;
            api_key = key;
        }

        // Try to access org2's project from org1
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}", org1_id, org2_project_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "accessing another org's project should return 404"
        );
    }

    #[tokio::test]
    async fn test_delete_project_removes_project() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "To Delete", &master_key);

            org_id = org.id;
            project_id = project.id.clone();
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/projects/{}", org_id, project_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "delete project should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["success"], true,
            "delete response should indicate success"
        );

        // Verify project is deleted
        let mut conn = state.db.get().unwrap();
        let project = queries::get_project_by_id(&mut conn, &project_id).unwrap();
        assert!(
            project.is_none(),
            "project should no longer exist in database"
        );
    }

    #[tokio::test]
    async fn test_delete_project_not_found_returns_error() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/projects/nonexistent-id", org_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "deleting nonexistent project should return 404"
        );
    }

    #[tokio::test]
    async fn test_delete_project_member_role_forbidden() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let member_api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            // Create member with "member" role (not admin)
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            member_api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/projects/{}", org_id, project_id))
                    .header("Authorization", format!("Bearer {}", member_api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Returns 404 (not 403) to avoid leaking project existence to unauthorized users
        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "member role should see 404 to avoid leaking project existence"
        );
    }

    #[tokio::test]
    async fn test_create_project_member_role_forbidden() {
        let (app, state) = org_app();

        let org_id: String;
        let member_api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);

            org_id = org.id;
            member_api_key = key;
        }

        let body = json!({
            "name": "New Project",
            "domain": "new.example.com",
            "license_key_prefix": "NEW"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects", org_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", member_api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "member role should not be able to create projects"
        );
    }

    #[tokio::test]
    async fn test_list_projects_member_role_only_sees_assigned_projects() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let member_api_key: String;
        let assigned_project_name: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_user, member, key) =
                create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);

            // Create 3 projects
            let project1 = create_test_project(&mut conn, &org.id, "Project 1", &master_key);
            let _project2 = create_test_project(&mut conn, &org.id, "Project 2", &master_key);
            let _project3 = create_test_project(&mut conn, &org.id, "Project 3", &master_key);

            // Only assign member to project1
            queries::create_project_member(
                &mut conn,
                &member.id,
                &project1.id,
                paycheck::models::ProjectMemberRole::View,
            )
            .unwrap();

            org_id = org.id;
            member_api_key = key;
            assigned_project_name = project1.name;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects", org_id))
                    .header("Authorization", format!("Bearer {}", member_api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "list projects should return 200 OK for member"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let projects = json["items"].as_array().unwrap();
        // Member should only see the one project they're assigned to
        assert_eq!(
            projects.len(),
            1,
            "member should only see assigned projects"
        );
        assert_eq!(
            projects[0]["name"], assigned_project_name,
            "member should see their assigned project"
        );
        assert_eq!(
            json["total"], 1,
            "total should reflect only assigned projects"
        );
    }

    #[tokio::test]
    async fn test_get_payment_config_returns_masked_configs() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

            // Setup both payment configs in one call to avoid overwriting
            setup_both_payment_configs(&mut conn, &org.id, &master_key);

            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/payment-provider", org_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "Expected OK, got {}: {}",
            status,
            body_str
        );

        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["org_id"], org_id, "response should include org ID");
        // Stripe config should be masked
        assert!(
            json["stripe_config"].is_object(),
            "stripe_config should be present as an object, got: {}",
            json
        );
        let stripe = &json["stripe_config"];
        let secret_key = stripe["secret_key"].as_str().unwrap();
        assert!(
            secret_key.contains("...") || secret_key.contains("*"),
            "stripe secret key should be masked for security, got: {}",
            secret_key
        );
        // LemonSqueezy config should be masked
        assert!(
            json["ls_config"].is_object(),
            "ls_config should be present as an object"
        );
        let ls = &json["ls_config"];
        let api_key = ls["api_key"].as_str().unwrap();
        assert!(
            api_key.contains("...") || api_key.contains("*"),
            "LemonSqueezy API key should be masked for security, got: {}",
            api_key
        );
    }

    #[tokio::test]
    async fn test_get_payment_config_no_configs_returns_nulls() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/payment-provider", org_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "get payment config should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["org_id"], org_id, "response should include org ID");
        assert!(
            json["stripe_config"].is_null(),
            "stripe_config should be null when not configured"
        );
        assert!(
            json["ls_config"].is_null(),
            "ls_config should be null when not configured"
        );
    }

    #[tokio::test]
    async fn test_get_payment_config_member_role_forbidden() {
        let (app, state) = org_app();

        let org_id: String;
        let member_api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);

            org_id = org.id;
            member_api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/payment-provider", org_id))
                    .header("Authorization", format!("Bearer {}", member_api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "member role should not access payment config"
        );
    }

    #[tokio::test]
    async fn test_update_project_not_found_returns_error() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

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
                    .uri(format!("/orgs/{}/projects/nonexistent-id", org_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "updating nonexistent project should return 404"
        );
    }
}

// ============================================================================
// ORG MEMBER TESTS
// ============================================================================

mod org_member_tests {
    use super::*;

    #[tokio::test]
    async fn test_list_org_members_returns_all_members() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Admin);
            create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);

            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members", org_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "list org members should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let members = json["items"].as_array().unwrap();
        assert_eq!(members.len(), 3, "should return all 3 org members");
        assert_eq!(json["total"], 3, "total count should be 3");
    }

    #[tokio::test]
    async fn test_create_org_member_returns_member() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;
        let new_user_id: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

            // Create user first (identity-based model)
            let new_user = create_test_user(&mut conn, "newmember@test.com", "New Member");

            org_id = org.id;
            api_key = key;
            new_user_id = new_user.id;
        }

        let body = json!({
            "user_id": new_user_id,
            "role": "admin"
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

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "create org member should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Response is OrgMemberWithUser (enriched with user details)
        assert_eq!(
            json["user_id"], new_user_id,
            "member should be linked to correct user"
        );
        assert_eq!(json["role"], "admin", "member role should match input");
        assert_eq!(
            json["email"], "newmember@test.com",
            "response should include user email"
        );
        assert_eq!(
            json["name"], "New Member",
            "response should include user name"
        );
    }

    #[tokio::test]
    async fn test_get_org_member_returns_member_details() {
        let (app, state) = org_app();

        let org_id: String;
        let target_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (target_user, _, _) =
                create_test_org_member(&mut conn, &org.id, "target@test.com", OrgMemberRole::Admin);

            org_id = org.id;
            target_user_id = target_user.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members/{}", org_id, target_user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "get org member should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["user_id"], target_user_id,
            "member user_id should match requested ID"
        );
        assert_eq!(
            json["email"], "target@test.com",
            "member email should be included"
        );
        assert_eq!(json["role"], "admin", "member role should match");
    }

    #[tokio::test]
    async fn test_get_org_member_wrong_org_returns_not_found() {
        let (app, state) = org_app();

        let org1_id: String;
        let org2_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org1 = create_test_org(&mut conn, "Org 1");
            let org2 = create_test_org(&mut conn, "Org 2");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org1.id, "owner@org1.com", OrgMemberRole::Owner);
            let (user2, _, _) =
                create_test_org_member(&mut conn, &org2.id, "member@org2.com", OrgMemberRole::Member);

            org1_id = org1.id;
            org2_user_id = user2.id;
            api_key = key;
        }

        // Try to get org2's member via org1's URL (user exists but not in org1)
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members/{}", org1_id, org2_user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "accessing member from another org should return 404"
        );
    }

    #[tokio::test]
    async fn test_update_org_member_changes_role() {
        let (app, state) = org_app();

        let org_id: String;
        let target_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (target_user, _, _) =
                create_test_org_member(&mut conn, &org.id, "target@test.com", OrgMemberRole::Member);

            org_id = org.id;
            target_user_id = target_user.id;
            api_key = key;
        }

        // UpdateOrgMember only has role field (name/email are on User now)
        let body = json!({
            "role": "admin"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/orgs/{}/members/{}", org_id, target_user_id))
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
            "update org member should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["role"], "admin",
            "member role should be updated to admin"
        );
    }

    #[tokio::test]
    async fn test_update_org_member_cannot_change_own_role() {
        let (app, state) = org_app();

        let org_id: String;
        let owner_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (owner_user, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

            org_id = org.id;
            owner_user_id = owner_user.id;
            api_key = key;
        }

        // Try to change own role
        let body = json!({
            "role": "member"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/orgs/{}/members/{}", org_id, owner_user_id))
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
            "users should not be able to change their own role"
        );
    }

    // NOTE: test_update_org_member_can_change_own_name removed
    // Name is now on User, not OrgMember. UpdateOrgMember only has role field.

    #[tokio::test]
    async fn test_delete_org_member_removes_member() {
        let (app, state) = org_app();

        let org_id: String;
        let target_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (target_user, _, _) =
                create_test_org_member(&mut conn, &org.id, "target@test.com", OrgMemberRole::Member);

            org_id = org.id;
            target_user_id = target_user.id.clone();
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/members/{}", org_id, target_user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "delete org member should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["success"], true,
            "delete response should indicate success"
        );

        // Verify member is removed from database (by user_id)
        let mut conn = state.db.get().unwrap();
        let result =
            queries::get_org_member_by_user_and_org(&mut conn, &target_user_id, &org_id).unwrap();
        assert!(
            result.is_none(),
            "member should no longer exist in database"
        );
    }

    #[tokio::test]
    async fn test_delete_org_member_cannot_delete_self() {
        let (app, state) = org_app();

        let org_id: String;
        let owner_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (owner_user, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

            org_id = org.id;
            owner_user_id = owner_user.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/members/{}", org_id, owner_user_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "users should not be able to delete themselves"
        );
    }

    #[tokio::test]
    async fn test_delete_org_member_not_found_returns_error() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/members/nonexistent-id", org_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "deleting nonexistent member should return 404"
        );
    }
}

// ============================================================================
// PROJECT MEMBER TESTS
// ============================================================================

mod project_member_tests {
    use super::*;

    #[tokio::test]
    async fn test_create_project_member_adds_member_to_project() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let target_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (target_user, _target, _) =
                create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            target_user_id = target_user.id;
            api_key = key;
        }

        let body = json!({
            "user_id": target_user_id,
            "role": "admin"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/members", org_id, project_id))
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
            "create project member should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Internal IDs are hidden, check user_id instead
        assert_eq!(
            json["user_id"], target_user_id,
            "project member should be linked to correct user"
        );
        assert_eq!(
            json["role"], "admin",
            "project member role should match input"
        );
        // Should include org member details
        assert_eq!(
            json["email"], "member@test.com",
            "response should include member email"
        );
    }

    #[tokio::test]
    async fn test_create_project_member_duplicate_returns_conflict() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let target_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (target_user, target, _) =
                create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

            // Already add member to project
            queries::create_project_member(
                &mut conn,
                &target.id,
                &project.id,
                paycheck::models::ProjectMemberRole::View,
            )
            .unwrap();

            org_id = org.id;
            project_id = project.id;
            target_user_id = target_user.id;
            api_key = key;
        }

        // Try to add again
        let body = json!({
            "user_id": target_user_id,
            "role": "admin"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/members", org_id, project_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::CONFLICT,
            "adding duplicate project member should return 409 conflict"
        );
    }

    #[tokio::test]
    async fn test_create_project_member_cross_org_returns_error() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org1_id: String;
        let project_id: String;
        let org2_member_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org1 = create_test_org(&mut conn, "Org 1");
            let org2 = create_test_org(&mut conn, "Org 2");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org1.id, "owner@org1.com", OrgMemberRole::Owner);
            let (_, org2_member, _) =
                create_test_org_member(&mut conn, &org2.id, "member@org2.com", OrgMemberRole::Member);
            let project = create_test_project(&mut conn, &org1.id, "Org1 Project", &master_key);

            org1_id = org1.id;
            project_id = project.id;
            org2_member_id = org2_member.id;
            api_key = key;
        }

        // Try to add org2's member to org1's project
        let body = json!({
            "org_member_id": org2_member_id,
            "role": "view"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/orgs/{}/projects/{}/members", org1_id, project_id))
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
            "adding member from another org should return 400"
        );
    }

    #[tokio::test]
    async fn test_list_project_members_returns_all_members_with_details() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (_, member1, _) =
                create_test_org_member(&mut conn, &org.id, "member1@test.com", OrgMemberRole::Member);
            let (_, member2, _) =
                create_test_org_member(&mut conn, &org.id, "member2@test.com", OrgMemberRole::Member);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

            // Add both members to project
            queries::create_project_member(
                &mut conn,
                &member1.id,
                &project.id,
                paycheck::models::ProjectMemberRole::Admin,
            )
            .unwrap();

            queries::create_project_member(
                &mut conn,
                &member2.id,
                &project.id,
                paycheck::models::ProjectMemberRole::View,
            )
            .unwrap();

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/projects/{}/members", org_id, project_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "list project members should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let members = json["items"].as_array().unwrap();
        assert_eq!(members.len(), 2, "should return both project members");
        assert_eq!(json["total"], 2, "total count should be 2");
        // Should include email/name details
        assert!(
            members[0]["email"].as_str().is_some(),
            "response should include member email"
        );
        assert!(
            members[0]["name"].as_str().is_some(),
            "response should include member name"
        );
    }

    #[tokio::test]
    async fn test_update_project_member_changes_role() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let member_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (member_user, member, _) =
                create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

            let _pm = queries::create_project_member(
                &mut conn,
                &member.id,
                &project.id,
                paycheck::models::ProjectMemberRole::View,
            )
            .unwrap();

            org_id = org.id;
            project_id = project.id;
            member_user_id = member_user.id;
            api_key = key;
        }

        let body = json!({
            "role": "admin"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/orgs/{}/projects/{}/members/{}",
                        org_id, project_id, member_user_id
                    ))
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
            "update project member should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Response is ProjectMemberWithDetails (enriched with user details)
        assert_eq!(
            json["role"], "admin",
            "updated member should have new role"
        );
        assert_eq!(
            json["user_id"], member_user_id,
            "response should include user_id"
        );
        assert_eq!(
            json["email"], "member@test.com",
            "response should include user email"
        );
    }

    #[tokio::test]
    async fn test_update_project_member_not_found_returns_error() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        let body = json!({
            "role": "admin"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/orgs/{}/projects/{}/members/nonexistent-id",
                        org_id, project_id
                    ))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "updating nonexistent project member should return 404"
        );
    }

    #[tokio::test]
    async fn test_delete_project_member_removes_from_project() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let member_user_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (member_user, member, _) =
                create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

            let _pm = queries::create_project_member(
                &mut conn,
                &member.id,
                &project.id,
                paycheck::models::ProjectMemberRole::View,
            )
            .unwrap();

            org_id = org.id;
            project_id = project.id;
            member_user_id = member_user.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/orgs/{}/projects/{}/members/{}",
                        org_id, project_id, member_user_id
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
            "delete project member should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["success"], true,
            "delete response should indicate success"
        );

        // Verify member list is empty
        let mut conn = state.db.get().unwrap();
        let members = queries::list_project_members(&mut conn, &project_id).unwrap();
        assert_eq!(
            members.len(),
            0,
            "project should have no members after deletion"
        );
    }

    #[tokio::test]
    async fn test_delete_project_member_not_found_returns_error() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/orgs/{}/projects/{}/members/nonexistent-id",
                        org_id, project_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "deleting nonexistent project member should return 404"
        );
    }
}

// ============================================================================
// PAYMENT CONFIG CRUD TESTS
// ============================================================================

mod provider_link_tests {
    use super::*;

    #[tokio::test]
    async fn test_create_provider_link_stripe() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        let body = json!({
            "provider": "stripe",
            "linked_id": "price_12345"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}/provider-links",
                        org_id, project_id, product_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "create stripe provider link should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["id"].is_string(), "response should include link ID");
        assert_eq!(json["provider"], "stripe", "provider should be stripe");
        assert_eq!(
            json["linked_id"], "price_12345",
            "linked_id should match input"
        );
    }

    #[tokio::test]
    async fn test_create_provider_link_lemonsqueezy() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        let body = json!({
            "provider": "lemonsqueezy",
            "linked_id": "variant_abc123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}/provider-links",
                        org_id, project_id, product_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "create LemonSqueezy provider link should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["id"].is_string(), "response should include link ID");
        assert_eq!(
            json["provider"], "lemonsqueezy",
            "provider should be lemonsqueezy"
        );
        assert_eq!(
            json["linked_id"], "variant_abc123",
            "linked_id should match input"
        );
    }

    #[tokio::test]
    async fn test_create_provider_link_duplicate_provider_fails() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            // Create first link
            create_test_provider_link(&mut conn, &product.id, "stripe", "price_123");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        // Try to create another stripe link - should fail
        let body = json!({
            "provider": "stripe",
            "linked_id": "price_different"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}/provider-links",
                        org_id, project_id, product_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            400,
            "duplicate provider link should return 400"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["details"].as_str().unwrap().contains("already exists"),
            "error should mention link already exists"
        );
    }

    #[tokio::test]
    async fn test_create_provider_link_product_not_found() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        let body = json!({
            "provider": "stripe",
            "linked_id": "price_12345"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/nonexistent-product/provider-links",
                        org_id, project_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            404,
            "creating link for nonexistent product should return 404"
        );
    }

    #[tokio::test]
    async fn test_list_provider_links() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            // Create two links
            create_test_provider_link(&mut conn, &product.id, "stripe", "price_123");
            create_test_provider_link(&mut conn, &product.id, "lemonsqueezy", "variant_abc");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}/provider-links",
                        org_id, project_id, product_id
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
            "list provider links should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let links = json.as_array().unwrap();
        assert_eq!(links.len(), 2, "should return both provider links");
    }

    #[tokio::test]
    async fn test_get_provider_link() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let link_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            let link = create_test_provider_link(&mut conn, &product.id, "stripe", "price_123");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            link_id = link.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}/provider-links/{}",
                        org_id, project_id, product_id, link_id
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
            "get provider link should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["id"], link_id, "link ID should match requested ID");
        assert_eq!(json["provider"], "stripe", "provider should match");
        assert_eq!(json["linked_id"], "price_123", "linked_id should match");
    }

    #[tokio::test]
    async fn test_get_provider_link_wrong_product_returns_404() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let other_product_id: String;
        let link_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
            let other_product = create_test_product(&mut conn, &project.id, "Other Plan", "enterprise");

            let link = create_test_provider_link(&mut conn, &product.id, "stripe", "price_123");

            org_id = org.id;
            project_id = project.id;
            other_product_id = other_product.id;
            link_id = link.id;
            api_key = key;
        }

        // Try to get link under wrong product
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}/provider-links/{}",
                        org_id, project_id, other_product_id, link_id
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
            "accessing link from wrong product should return 404"
        );
    }

    #[tokio::test]
    async fn test_update_provider_link() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let link_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            let link = create_test_provider_link(&mut conn, &product.id, "stripe", "price_old");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            link_id = link.id;
            api_key = key;
        }

        let body = json!({
            "linked_id": "price_new"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}/provider-links/{}",
                        org_id, project_id, product_id, link_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "update provider link should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["linked_id"], "price_new",
            "linked_id should be updated"
        );
        // Provider should remain unchanged
        assert_eq!(json["provider"], "stripe", "provider should remain unchanged");
    }

    #[tokio::test]
    async fn test_delete_provider_link() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let link_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            let link = create_test_provider_link(&mut conn, &product.id, "stripe", "price_123");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            link_id = link.id.clone();
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}/provider-links/{}",
                        org_id, project_id, product_id, link_id
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
            "delete provider link should return 200 OK"
        );

        // Verify link is deleted
        let mut conn = state.db.get().unwrap();
        use paycheck::db::queries;
        let link = queries::get_provider_link_by_id(&mut conn, &link_id).unwrap();
        assert!(link.is_none(), "link should no longer exist in database");
    }

    #[tokio::test]
    async fn test_delete_provider_link_not_found() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}/provider-links/nonexistent-id",
                        org_id, project_id, product_id
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
            "deleting nonexistent link should return 404"
        );
    }

    #[tokio::test]
    async fn test_provider_link_requires_write_permission() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            // Create member with Member role (not Owner/Admin)
            let (_, member, key) =
                create_test_org_member(&mut conn, &org.id, "viewer@test.com", OrgMemberRole::Member);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            // Give member view access to project
            use paycheck::db::queries;
            queries::create_project_member(
                &conn,
                &member.id,
                &project.id,
                paycheck::models::ProjectMemberRole::View,
            )
            .unwrap();

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        // Try to create provider link - should fail
        let body = json!({
            "provider": "stripe",
            "linked_id": "price_123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}/provider-links",
                        org_id, project_id, product_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            403,
            "view-only access should not be able to create provider link"
        );
    }
}
