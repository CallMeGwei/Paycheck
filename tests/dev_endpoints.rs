//! Tests for payment config endpoints.
//!
//! - Org endpoint: GET /orgs/{org_id}/payment-config (masked, for customers)
//! - Operator endpoint: GET /operators/organizations/{org_id}/payment-config (full, for support)

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;

mod common;
use common::*;

use paycheck::db::AppState;
use paycheck::models::{LemonSqueezyConfig, StripeConfig, UpdateOrganization};

// ============ Operator Endpoint Tests (without auth middleware for simplicity) ============

fn operator_app_with_payment_configs() -> (Router, String) {
    use axum::routing::get;
    use paycheck::handlers::operators::get_org_payment_config;

    let master_key = test_master_key();

    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();

    let org_id: String;
    {
        let conn = pool.get().unwrap();
        paycheck::db::init_db(&conn).unwrap();

        // Create test data
        let org = create_test_org(&conn, "Test Org");
        org_id = org.id.clone();

        // Add payment configs to organization
        let update = UpdateOrganization {
            name: None,
            stripe_config: Some(StripeConfig {
                secret_key: "sk_test_abc123xyz789".to_string(),
                publishable_key: "pk_test_abc123xyz789".to_string(),
                webhook_secret: "whsec_test123secret456".to_string(),
            }),
            ls_config: Some(LemonSqueezyConfig {
                api_key: "ls_test_key_abcdefghij".to_string(),
                store_id: "store_123".to_string(),
                webhook_secret: "ls_whsec_test_secret".to_string(),
            }),
            resend_api_key: None,
            default_provider: Some(Some("stripe".to_string())),
        };

        queries::update_organization(&conn, &org.id, &update, &master_key)
            .expect("Failed to update organization with payment configs");
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

    // Note: Testing without auth middleware - auth is tested separately
    let app = Router::new()
        .route(
            "/operators/organizations/{org_id}/payment-config",
            get(get_org_payment_config),
        )
        .with_state(state);

    (app, org_id)
}

#[tokio::test]
async fn test_operator_get_payment_config_full_unmasked() {
    let (app, org_id) = operator_app_with_payment_configs();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/operators/organizations/{}/payment-config",
                    org_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(json["org_id"], org_id);

    // Verify Stripe config is FULL (unmasked)
    let stripe = &json["stripe_config"];
    assert!(!stripe.is_null());
    assert_eq!(stripe["secret_key"], "sk_test_abc123xyz789");
    assert_eq!(stripe["webhook_secret"], "whsec_test123secret456");

    // Verify LemonSqueezy config is FULL (unmasked)
    let ls = &json["ls_config"];
    assert!(!ls.is_null());
    assert_eq!(ls["api_key"], "ls_test_key_abcdefghij");
    assert_eq!(ls["webhook_secret"], "ls_whsec_test_secret");
}

#[tokio::test]
async fn test_operator_get_payment_config_nonexistent_org() {
    let (app, _org_id) = operator_app_with_payment_configs();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators/organizations/nonexistent-id/payment-config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_operator_get_payment_config_no_configs() {
    use axum::routing::get;
    use paycheck::handlers::operators::get_org_payment_config;

    let master_key = test_master_key();

    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();

    let org_id: String;
    {
        let conn = pool.get().unwrap();
        paycheck::db::init_db(&conn).unwrap();

        let org = create_test_org(&conn, "Test Org");
        org_id = org.id.clone();
        // No payment configs added
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

    let app = Router::new()
        .route(
            "/operators/organizations/{org_id}/payment-config",
            get(get_org_payment_config),
        )
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/operators/organizations/{}/payment-config",
                    org_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert!(json["stripe_config"].is_null());
    assert!(json["ls_config"].is_null());
}

// ============ Config Masking Tests ============

#[test]
fn test_stripe_config_masking() {
    use paycheck::models::StripeConfigMasked;

    let config = StripeConfig {
        secret_key: "sk_test_abc123xyz789".to_string(),
        publishable_key: "pk_test_abc123xyz789".to_string(),
        webhook_secret: "whsec_test123secret456".to_string(),
    };

    let masked: StripeConfigMasked = (&config).into();

    // secret_key should be masked
    assert!(
        masked.secret_key.contains("..."),
        "Secret key should be masked"
    );
    assert!(
        masked.secret_key.starts_with("sk_test_"),
        "Should preserve prefix"
    );
    assert!(
        !masked.secret_key.contains("abc123xyz789"),
        "Should not contain full key"
    );

    // publishable_key should NOT be masked (it's public)
    assert_eq!(masked.publishable_key, "pk_test_abc123xyz789");

    // webhook_secret should be masked
    assert!(
        masked.webhook_secret.contains("..."),
        "Webhook secret should be masked"
    );
}

#[test]
fn test_lemonsqueezy_config_masking() {
    use paycheck::models::LemonSqueezyConfigMasked;

    let config = LemonSqueezyConfig {
        api_key: "ls_test_key_abcdefghij".to_string(),
        store_id: "store_123".to_string(),
        webhook_secret: "ls_whsec_test_secret".to_string(),
    };

    let masked: LemonSqueezyConfigMasked = (&config).into();

    // api_key should be masked
    assert!(masked.api_key.contains("..."), "API key should be masked");

    // store_id should NOT be masked
    assert_eq!(masked.store_id, "store_123");

    // webhook_secret should be masked
    assert!(
        masked.webhook_secret.contains("..."),
        "Webhook secret should be masked"
    );
}

#[test]
fn test_masking_short_secrets() {
    use paycheck::models::StripeConfigMasked;

    let config = StripeConfig {
        secret_key: "short".to_string(), // Too short to mask meaningfully
        publishable_key: "pk".to_string(),
        webhook_secret: "tiny".to_string(),
    };

    let masked: StripeConfigMasked = (&config).into();

    // Short secrets should be fully replaced with asterisks
    assert!(
        !masked.secret_key.contains("short"),
        "Short secret should be fully masked"
    );
    assert!(
        masked.secret_key.contains("*"),
        "Should use asterisks for short secrets"
    );
}
