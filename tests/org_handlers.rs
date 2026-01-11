//! Integration tests for org API handlers.
//!
//! These tests verify the business logic and response formats for all org-level
//! API endpoints, complementing the authorization tests in auth.rs.

use axum::{Router, body::Body, http::Request};
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::*;

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
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: std::sync::Arc::new(
            paycheck::rate_limit::ActivationRateLimiter::default(),
        ),
        email_service: std::sync::Arc::new(paycheck::email::EmailService::new(None, "test@example.com".to_string())),
    };

    let app = handlers::orgs::router(state.clone(), paycheck::config::RateLimitConfig::disabled()).with_state(state.clone());

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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_user, _member, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        let body = json!({
            "name": "Pro Plan",
            "tier": "pro",
            "license_exp_days": 365,
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["id"].as_str().is_some());
        assert_eq!(json["name"], "Pro Plan");
        assert_eq!(json["tier"], "pro");
        assert_eq!(json["license_exp_days"], 365);
        assert_eq!(json["updates_exp_days"], 180);
        assert_eq!(json["activation_limit"], 10);
        assert_eq!(json["device_limit"], 5);
        assert_eq!(
            json["features"],
            json!(["feature1", "feature2", "advanced"])
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            // Create multiple products
            create_test_product(&conn, &project.id, "Free Plan", "free");
            create_test_product(&conn, &project.id, "Pro Plan", "pro");
            create_test_product(&conn, &project.id, "Enterprise", "enterprise");

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let products = json["items"].as_array().unwrap();
        assert_eq!(products.len(), 3);
        assert_eq!(json["total"], 3);
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["id"], product_id);
        assert_eq!(json["name"], "Pro Plan");
        assert_eq!(json["tier"], "pro");
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["name"], "Pro Plan Plus");
        assert_eq!(json["tier"], "pro_plus");
        assert_eq!(json["device_limit"], 10);
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);

        // Verify product is actually deleted
        let conn = state.db.get().unwrap();
        let result = queries::get_product_by_id(&conn, &product_id).unwrap();
        assert!(result.is_none());
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project1 = create_test_project(&conn, &org.id, "Project 1", &master_key);
            let project2 = create_test_project(&conn, &org.id, "Project 2", &master_key);
            let product2 = create_test_product(&conn, &project2.id, "Pro Plan", "pro");

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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let licenses = json["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 1);
        assert!(licenses[0]["id"].as_str().is_some());
        // Note: "key" field no longer exists (email-only activation model)
        assert!(licenses[0]["expires_at"].as_i64().is_some()); // Product has 365 day expiration
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        let body = json!({
            "product_id": product_id,
            "count": 5
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let licenses = json["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 5);

        // All IDs should be unique
        let ids: Vec<&str> = licenses
            .iter()
            .map(|l| l["id"].as_str().unwrap())
            .collect();
        let unique_ids: std::collections::HashSet<&str> = ids.iter().cloned().collect();
        assert_eq!(ids.len(), unique_ids.len());
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

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

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        // Override to 30 day expiration
        let body = json!({
            "product_id": product_id,
            "license_exp_days": 30,
            "updates_exp_days": 60
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let licenses = json["licenses"].as_array().unwrap();
        let license_exp = licenses[0]["expires_at"].as_i64().unwrap();
        let updates_exp = licenses[0]["updates_expires_at"].as_i64().unwrap();

        // Should be ~30 days from now
        assert!(license_exp >= before + (30 * 86400) - 5);
        assert!(license_exp <= before + (30 * 86400) + 5);

        // Updates should be ~60 days from now
        assert!(updates_exp >= before + (60 * 86400) - 5);
        assert!(updates_exp <= before + (60 * 86400) + 5);
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            // Create a perpetual product (no expiration)
            let input = paycheck::models::CreateProduct {
                name: "Lifetime".to_string(),
                tier: "lifetime".to_string(),
                license_exp_days: None,
                updates_exp_days: None,
                activation_limit: 5,
                device_limit: 3,
                features: vec![],
            };
            let product = queries::create_product(&conn, &project.id, &input).unwrap();

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        // Don't specify any expiration override - use product defaults (which are perpetual)
        let body = json!({
            "product_id": product_id
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let licenses = json["licenses"].as_array().unwrap();
        assert!(
            licenses[0]["expires_at"].is_null(),
            "Perpetual license should have null expires_at"
        );
        assert!(
            licenses[0]["updates_expires_at"].is_null(),
            "Perpetual license should have null updates_expires_at"
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license = create_test_license(
                &conn,
                &project.id,
                &product.id,
                Some(future_timestamp(365)),
            );

            // Create a device for the license
            create_test_device(&conn, &license.id, "device-1", DeviceType::Uuid);

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Verify license fields
        assert_eq!(json["id"], license_id);
        assert!(json["product_name"].as_str().is_some());

        // Verify devices array
        let devices = json["devices"].as_array().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0]["device_id"], "device-1");
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license = create_test_license(
                &conn,
                &project.id,
                &product.id,
                Some(future_timestamp(365)),
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);

        // Verify in database
        let conn = state.db.get().unwrap();
        let license = queries::get_license_by_id(&conn, &license_id)
            .unwrap()
            .unwrap();
        assert!(license.revoked);
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license = create_test_license(
                &conn,
                &project.id,
                &product.id,
                Some(future_timestamp(365)),
            );

            // Pre-revoke the license
            queries::revoke_license(&conn, &license.id).unwrap();

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

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license = create_test_license(
                &conn,
                &project.id,
                &product.id,
                Some(future_timestamp(365)),
            );

            // Create devices
            create_test_device(&conn, &license.id, "device-1", DeviceType::Uuid);
            create_test_device(&conn, &license.id, "device-2", DeviceType::Uuid);

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["deactivated"], true);
        assert_eq!(json["device_id"], device_id);
        assert_eq!(json["remaining_devices"], 1); // Was 2, now 1

        // Verify device is removed from database
        let conn = state.db.get().unwrap();
        let devices = queries::list_devices_for_license(&conn, &license_id).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, "device-2");
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["id"].as_str().is_some());
        assert_eq!(json["name"], "My New Project");
        assert_eq!(json["license_key_prefix"], "MNP");
        assert_eq!(json["redirect_url"], "https://myapp.com/activated");
        // Public key should be present (for client-side JWT verification)
        assert!(json["public_key"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_list_projects_returns_all_org_projects() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

            // Create multiple projects
            create_test_project(&conn, &org.id, "Project 1", &master_key);
            create_test_project(&conn, &org.id, "Project 2", &master_key);
            create_test_project(&conn, &org.id, "Project 3", &master_key);

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let projects = json["items"].as_array().unwrap();
        assert_eq!(projects.len(), 3);
        assert_eq!(json["total"], 3);
    }

    #[tokio::test]
    async fn test_update_project_changes_fields() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Original Name", &master_key);

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["name"], "Updated Name");
    }

    #[tokio::test]
    async fn test_get_project_returns_project_details() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "My Project", &master_key);

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["id"], project_id);
        assert_eq!(json["name"], "My Project");
        assert!(json["public_key"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_get_project_not_found_returns_error() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_project_cross_org_returns_not_found() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org1_id: String;
        let org2_project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org1 = create_test_org(&conn, "Org 1");
            let org2 = create_test_org(&conn, "Org 2");
            let (_, _, key) =
                create_test_org_member(&conn, &org1.id, "admin@test.com", OrgMemberRole::Owner);
            let project2 = create_test_project(&conn, &org2.id, "Org2 Project", &master_key);

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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_project_removes_project() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "To Delete", &master_key);

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);

        // Verify project is deleted
        let conn = state.db.get().unwrap();
        let project = queries::get_project_by_id(&conn, &project_id).unwrap();
        assert!(project.is_none());
    }

    #[tokio::test]
    async fn test_delete_project_not_found_returns_error() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_project_member_role_forbidden() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let member_api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            // Create member with "member" role (not admin)
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Member);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

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
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_project_member_role_forbidden() {
        let (app, state) = org_app();

        let org_id: String;
        let member_api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Member);

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

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_projects_member_role_only_sees_assigned_projects() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let member_api_key: String;
        let assigned_project_name: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_user, member, key) =
                create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Member);

            // Create 3 projects
            let project1 = create_test_project(&conn, &org.id, "Project 1", &master_key);
            let _project2 = create_test_project(&conn, &org.id, "Project 2", &master_key);
            let _project3 = create_test_project(&conn, &org.id, "Project 3", &master_key);

            // Only assign member to project1
            let input = paycheck::models::CreateProjectMember {
                org_member_id: member.id.clone(),
                role: paycheck::models::ProjectMemberRole::View,
            };
            queries::create_project_member(&conn, &project1.id, &input).unwrap();

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let projects = json["items"].as_array().unwrap();
        // Member should only see the one project they're assigned to
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0]["name"], assigned_project_name);
        assert_eq!(json["total"], 1);
    }

    #[tokio::test]
    async fn test_get_payment_config_returns_masked_configs() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

            // Setup both payment configs in one call to avoid overwriting
            setup_both_payment_configs(&conn, &org.id, &master_key);

            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/payment-config", org_id))
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

        assert_eq!(json["org_id"], org_id);
        // Stripe config should be masked
        assert!(
            json["stripe_config"].is_object(),
            "Expected stripe_config to be object, got: {}",
            json
        );
        let stripe = &json["stripe_config"];
        let secret_key = stripe["secret_key"].as_str().unwrap();
        assert!(
            secret_key.contains("...") || secret_key.contains("*"),
            "Secret key should be masked, got: {}",
            secret_key
        );
        // LemonSqueezy config should be masked
        assert!(json["ls_config"].is_object());
        let ls = &json["ls_config"];
        let api_key = ls["api_key"].as_str().unwrap();
        assert!(
            api_key.contains("...") || api_key.contains("*"),
            "API key should be masked, got: {}",
            api_key
        );
    }

    #[tokio::test]
    async fn test_get_payment_config_no_configs_returns_nulls() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

            org_id = org.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/payment-config", org_id))
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
        assert!(json["stripe_config"].is_null());
        assert!(json["ls_config"].is_null());
    }

    #[tokio::test]
    async fn test_get_payment_config_member_role_forbidden() {
        let (app, state) = org_app();

        let org_id: String;
        let member_api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Member);

            org_id = org.id;
            member_api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/payment-config", org_id))
                    .header("Authorization", format!("Bearer {}", member_api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_update_project_not_found_returns_error() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
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
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Admin);
            create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Member);

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let members = json["items"].as_array().unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(json["total"], 3);
    }

    #[tokio::test]
    async fn test_create_org_member_returns_member() {
        let (app, state) = org_app();

        let org_id: String;
        let api_key: String;
        let new_user_id: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

            // Create user first (identity-based model)
            let new_user = create_test_user(&conn, "newmember@test.com", "New Member");

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Response is OrgMember (user_id linked, no email/name in response)
        assert!(json["id"].as_str().is_some());
        assert_eq!(json["user_id"], new_user_id);
        assert_eq!(json["role"], "admin");
    }

    #[tokio::test]
    async fn test_get_org_member_returns_member_details() {
        let (app, state) = org_app();

        let org_id: String;
        let member_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (_, member, _) =
                create_test_org_member(&conn, &org.id, "target@test.com", OrgMemberRole::Admin);

            org_id = org.id;
            member_id = member.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members/{}", org_id, member_id))
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

        assert_eq!(json["id"], member_id);
        assert_eq!(json["email"], "target@test.com");
        assert_eq!(json["role"], "admin");
    }

    #[tokio::test]
    async fn test_get_org_member_wrong_org_returns_not_found() {
        let (app, state) = org_app();

        let org1_id: String;
        let org2_member_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org1 = create_test_org(&conn, "Org 1");
            let org2 = create_test_org(&conn, "Org 2");
            let (_, _, key) =
                create_test_org_member(&conn, &org1.id, "owner@org1.com", OrgMemberRole::Owner);
            let (_, member2, _) =
                create_test_org_member(&conn, &org2.id, "member@org2.com", OrgMemberRole::Member);

            org1_id = org1.id;
            org2_member_id = member2.id;
            api_key = key;
        }

        // Try to get org2's member via org1's URL
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/orgs/{}/members/{}", org1_id, org2_member_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_org_member_changes_role() {
        let (app, state) = org_app();

        let org_id: String;
        let member_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (_, member, _) =
                create_test_org_member(&conn, &org.id, "target@test.com", OrgMemberRole::Member);

            org_id = org.id;
            member_id = member.id;
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
                    .uri(format!("/orgs/{}/members/{}", org_id, member_id))
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

        assert_eq!(json["role"], "admin");
    }

    #[tokio::test]
    async fn test_update_org_member_cannot_change_own_role() {
        let (app, state) = org_app();

        let org_id: String;
        let owner_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, owner, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

            org_id = org.id;
            owner_id = owner.id;
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
                    .uri(format!("/orgs/{}/members/{}", org_id, owner_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    // NOTE: test_update_org_member_can_change_own_name removed
    // Name is now on User, not OrgMember. UpdateOrgMember only has role field.

    #[tokio::test]
    async fn test_delete_org_member_removes_member() {
        let (app, state) = org_app();

        let org_id: String;
        let member_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (_, member, _) =
                create_test_org_member(&conn, &org.id, "target@test.com", OrgMemberRole::Member);

            org_id = org.id;
            member_id = member.id.clone();
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/members/{}", org_id, member_id))
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

        // Verify member is removed from database
        let conn = state.db.get().unwrap();
        let result = queries::get_org_member_by_id(&conn, &member_id).unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_org_member_cannot_delete_self() {
        let (app, state) = org_app();

        let org_id: String;
        let owner_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, owner, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

            org_id = org.id;
            owner_id = owner.id;
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/orgs/{}/members/{}", org_id, owner_id))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_org_member_not_found_returns_error() {
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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
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
        let target_member_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (_, target, _) =
                create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Member);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            org_id = org.id;
            project_id = project.id;
            target_member_id = target.id;
            api_key = key;
        }

        let body = json!({
            "org_member_id": target_member_id,
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["id"].as_str().is_some());
        assert_eq!(json["org_member_id"], target_member_id);
        assert_eq!(json["role"], "admin");
        // Should include org member details
        assert_eq!(json["email"], "member@test.com");
    }

    #[tokio::test]
    async fn test_create_project_member_duplicate_returns_conflict() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let target_member_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (_, target, _) =
                create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Member);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            // Already add member to project
            let input = paycheck::models::CreateProjectMember {
                org_member_id: target.id.clone(),
                role: paycheck::models::ProjectMemberRole::View,
            };
            queries::create_project_member(&conn, &project.id, &input).unwrap();

            org_id = org.id;
            project_id = project.id;
            target_member_id = target.id;
            api_key = key;
        }

        // Try to add again
        let body = json!({
            "org_member_id": target_member_id,
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

        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
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
            let conn = state.db.get().unwrap();
            let org1 = create_test_org(&conn, "Org 1");
            let org2 = create_test_org(&conn, "Org 2");
            let (_, _, key) =
                create_test_org_member(&conn, &org1.id, "owner@org1.com", OrgMemberRole::Owner);
            let (_, org2_member, _) =
                create_test_org_member(&conn, &org2.id, "member@org2.com", OrgMemberRole::Member);
            let project = create_test_project(&conn, &org1.id, "Org1 Project", &master_key);

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

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_list_project_members_returns_all_members_with_details() {
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
            let (_, member1, _) =
                create_test_org_member(&conn, &org.id, "member1@test.com", OrgMemberRole::Member);
            let (_, member2, _) =
                create_test_org_member(&conn, &org.id, "member2@test.com", OrgMemberRole::Member);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            // Add both members to project
            let input1 = paycheck::models::CreateProjectMember {
                org_member_id: member1.id,
                role: paycheck::models::ProjectMemberRole::Admin,
            };
            queries::create_project_member(&conn, &project.id, &input1).unwrap();

            let input2 = paycheck::models::CreateProjectMember {
                org_member_id: member2.id,
                role: paycheck::models::ProjectMemberRole::View,
            };
            queries::create_project_member(&conn, &project.id, &input2).unwrap();

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

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let members = json["items"].as_array().unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(json["total"], 2);
        // Should include email/name details
        assert!(members[0]["email"].as_str().is_some());
        assert!(members[0]["name"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_update_project_member_changes_role() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let pm_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (_, member, _) =
                create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Member);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            let input = paycheck::models::CreateProjectMember {
                org_member_id: member.id,
                role: paycheck::models::ProjectMemberRole::View,
            };
            let pm = queries::create_project_member(&conn, &project.id, &input).unwrap();

            org_id = org.id;
            project_id = project.id;
            pm_id = pm.id;
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
                        org_id, project_id, pm_id
                    ))
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

        assert_eq!(json["updated"], true);
    }

    #[tokio::test]
    async fn test_update_project_member_not_found_returns_error() {
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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_project_member_removes_from_project() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let pm_id: String;
        let api_key: String;

        {
            let conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_, _, key) =
                create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
            let (_, member, _) =
                create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Member);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

            let input = paycheck::models::CreateProjectMember {
                org_member_id: member.id,
                role: paycheck::models::ProjectMemberRole::View,
            };
            let pm = queries::create_project_member(&conn, &project.id, &input).unwrap();

            org_id = org.id;
            project_id = project.id;
            pm_id = pm.id.clone();
            api_key = key;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/orgs/{}/projects/{}/members/{}",
                        org_id, project_id, pm_id
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

        assert_eq!(json["success"], true);

        // Verify member list is empty
        let conn = state.db.get().unwrap();
        let members = queries::list_project_members(&conn, &project_id).unwrap();
        assert_eq!(members.len(), 0);
    }

    #[tokio::test]
    async fn test_delete_project_member_not_found_returns_error() {
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

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }
}
