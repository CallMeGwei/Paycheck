//! Test utilities and fixtures for Paycheck integration tests

#![allow(dead_code)]

use axum::Router;
use axum::routing::{get, post};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use std::sync::Arc;

// Re-export the main library crate
pub use paycheck::crypto::MasterKey;
pub use paycheck::db::{AppState, init_audit_db, init_db, queries};
pub use paycheck::email::EmailService;
pub use paycheck::handlers::public::{
    deactivate_device, get_license_info, initiate_buy, payment_callback,
    redeem_with_code, request_activation_code, validate_license,
};
pub use paycheck::jwt;
pub use paycheck::models::*;
pub use paycheck::rate_limit::ActivationRateLimiter;

/// Create a test master key (deterministic for testing)
pub fn test_master_key() -> MasterKey {
    // Use a fixed test key (32 bytes of zeros - ONLY for testing!)
    MasterKey::from_bytes([0u8; 32])
}

/// Create an in-memory test database with schema initialized
pub fn setup_test_db() -> Connection {
    let conn = Connection::open_in_memory().expect("Failed to create in-memory database");
    init_db(&conn).expect("Failed to initialize schema");
    conn
}

/// Create a test operator with default values
pub fn create_test_operator(
    conn: &Connection,
    email: &str,
    role: OperatorRole,
) -> (Operator, String) {
    let api_key = queries::generate_api_key();
    let input = CreateOperator {
        email: email.to_string(),
        name: format!("Test Operator {}", email),
        role,
    };
    let operator = queries::create_operator(conn, &input, &api_key, None)
        .expect("Failed to create test operator");
    (operator, api_key)
}

/// Create a test organization
pub fn create_test_org(conn: &Connection, name: &str) -> Organization {
    let input = CreateOrganization {
        name: name.to_string(),
        owner_email: None,
        owner_name: None,
    };
    queries::create_organization(conn, &input).expect("Failed to create test organization")
}

/// Create a test org member with default values
pub fn create_test_org_member(
    conn: &Connection,
    org_id: &str,
    email: &str,
    role: OrgMemberRole,
) -> (OrgMember, String) {
    let api_key = queries::generate_api_key();
    let input = CreateOrgMember {
        email: email.to_string(),
        name: format!("Test Member {}", email),
        role,
    };
    let member = queries::create_org_member(conn, org_id, &input, &api_key)
        .expect("Failed to create test org member");
    (member, api_key)
}

/// Create a test project with auto-generated keypair and encrypted private key
pub fn create_test_project(
    conn: &Connection,
    org_id: &str,
    name: &str,
    master_key: &MasterKey,
) -> Project {
    let input = CreateProject {
        name: name.to_string(),
        domain: format!("{}.example.com", name.to_lowercase().replace(' ', "-")),
        license_key_prefix: "TEST".to_string(),
        allowed_redirect_urls: vec![],
        email_from: None,
        email_enabled: true,
        email_webhook_url: None,
    };
    let (private_key, public_key) = jwt::generate_keypair();
    queries::create_project(conn, org_id, &input, &private_key, &public_key, master_key)
        .expect("Failed to create test project")
}

/// Create a test product
pub fn create_test_product(conn: &Connection, project_id: &str, name: &str, tier: &str) -> Product {
    let input = CreateProduct {
        name: name.to_string(),
        tier: tier.to_string(),
        license_exp_days: Some(365),
        updates_exp_days: Some(365),
        activation_limit: 5,
        device_limit: 3,
        features: vec!["feature1".to_string(), "feature2".to_string()],
    };
    queries::create_product(conn, project_id, &input).expect("Failed to create test product")
}

/// Create a test payment config for a product
pub fn create_test_payment_config(
    conn: &Connection,
    product_id: &str,
    provider: &str,
    price_cents: Option<i64>,
) -> ProductPaymentConfig {
    let input = CreatePaymentConfig {
        provider: provider.to_string(),
        stripe_price_id: None,
        price_cents,
        currency: Some("usd".to_string()),
        ls_variant_id: if provider == "lemonsqueezy" {
            Some("test_variant_123".to_string())
        } else {
            None
        },
    };
    queries::create_payment_config(conn, product_id, &input)
        .expect("Failed to create test payment config")
}

/// Create a test license (no longer uses master_key - email hash is the identity)
pub fn create_test_license(
    conn: &Connection,
    project_id: &str,
    product_id: &str,
    expires_at: Option<i64>,
) -> License {
    let input = CreateLicense {
        email_hash: Some(queries::hash_email("test@example.com")),
        customer_id: Some("test-customer".to_string()),
        expires_at,
        updates_expires_at: expires_at,
        payment_provider: None,
        payment_provider_customer_id: None,
        payment_provider_subscription_id: None,
        payment_provider_order_id: None,
    };
    queries::create_license(conn, project_id, product_id, &input)
        .expect("Failed to create test license")
}

/// Create a test device for a license
pub fn create_test_device(
    conn: &Connection,
    license_id: &str,
    device_id: &str,
    device_type: DeviceType,
) -> Device {
    let jti = uuid::Uuid::new_v4().to_string();
    queries::create_device(
        conn,
        license_id,
        device_id,
        device_type,
        &jti,
        Some("Test Device"),
    )
    .expect("Failed to create test device")
}

/// Get the current timestamp
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Get a future timestamp (days from now)
pub fn future_timestamp(days: i64) -> i64 {
    now() + (days * 86400)
}

/// Get a past timestamp (days ago)
pub fn past_timestamp(days: i64) -> i64 {
    now() - (days * 86400)
}

/// Create an AppState for testing with in-memory databases
pub fn create_test_app_state() -> AppState {
    let master_key = test_master_key();

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();
    {
        let conn = pool.get().unwrap();
        init_db(&conn).unwrap();
    }

    let audit_manager = SqliteConnectionManager::memory();
    let audit_pool = Pool::builder().max_size(4).build(audit_manager).unwrap();
    {
        let conn = audit_pool.get().unwrap();
        init_audit_db(&conn).unwrap();
    }

    AppState {
        db: pool,
        audit: audit_pool,
        base_url: "http://localhost:3000".to_string(),
        audit_log_enabled: false,
        master_key,
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: Arc::new(ActivationRateLimiter::default()),
        email_service: Arc::new(EmailService::new(None, "test@example.com".to_string())),
    }
}

/// Create a Router with all public endpoints (without rate limiting for tests)
pub fn public_app(state: AppState) -> Router {
    Router::new()
        .route("/buy", post(initiate_buy))
        .route("/callback", get(payment_callback))
        .route("/redeem", get(redeem_with_code))
        .route("/activation/request-code", post(request_activation_code))
        .route("/validate", get(validate_license))
        .route("/license", get(get_license_info))
        .route("/devices/deactivate", post(deactivate_device))
        .with_state(state)
}

/// Create a test payment session.
/// Note: Device info is NOT stored in payment sessions - purchase ≠ activation.
pub fn create_test_payment_session(
    conn: &Connection,
    product_id: &str,
    customer_id: Option<&str>,
    redirect_url: Option<&str>,
) -> PaymentSession {
    let input = CreatePaymentSession {
        product_id: product_id.to_string(),
        customer_id: customer_id.map(|s| s.to_string()),
        redirect_url: redirect_url.map(|s| s.to_string()),
    };
    queries::create_payment_session(conn, &input).expect("Failed to create test payment session")
}

/// Mark a payment session as completed and associate it with a license
pub fn complete_payment_session(conn: &Connection, session_id: &str, license_id: &str) {
    queries::try_claim_payment_session(conn, session_id).expect("Failed to claim payment session");
    queries::set_payment_session_license(conn, session_id, license_id)
        .expect("Failed to set payment session license");
}

/// Set up Stripe config for an organization
pub fn setup_stripe_config(conn: &Connection, org_id: &str, master_key: &MasterKey) {
    let config = StripeConfig {
        secret_key: "sk_test_xxx".to_string(),
        publishable_key: "pk_test_xxx".to_string(),
        webhook_secret: "whsec_test_secret".to_string(),
    };
    let config_json = serde_json::to_vec(&config).expect("Failed to serialize Stripe config");
    let encrypted = master_key
        .encrypt_private_key(org_id, &config_json)
        .expect("Failed to encrypt Stripe config");
    queries::update_organization_encrypted_configs(conn, org_id, Some(&encrypted), None, None)
        .expect("Failed to set Stripe config");
}

/// Set up LemonSqueezy config for an organization
pub fn setup_lemonsqueezy_config(conn: &Connection, org_id: &str, master_key: &MasterKey) {
    let config = LemonSqueezyConfig {
        api_key: "lskey_test_xxx".to_string(),
        store_id: "12345".to_string(),
        webhook_secret: "ls_test_secret".to_string(),
    };
    let config_json = serde_json::to_vec(&config).expect("Failed to serialize LS config");
    let encrypted = master_key
        .encrypt_private_key(org_id, &config_json)
        .expect("Failed to encrypt LS config");
    queries::update_organization_encrypted_configs(conn, org_id, None, Some(&encrypted), None)
        .expect("Failed to set LemonSqueezy config");
}

/// Set up both Stripe and LemonSqueezy configs for an organization
pub fn setup_both_payment_configs(conn: &Connection, org_id: &str, master_key: &MasterKey) {
    let stripe_config = StripeConfig {
        secret_key: "sk_test_xxx".to_string(),
        publishable_key: "pk_test_xxx".to_string(),
        webhook_secret: "whsec_test_secret".to_string(),
    };
    let stripe_json =
        serde_json::to_vec(&stripe_config).expect("Failed to serialize Stripe config");
    let stripe_encrypted = master_key
        .encrypt_private_key(org_id, &stripe_json)
        .expect("Failed to encrypt Stripe config");

    let ls_config = LemonSqueezyConfig {
        api_key: "lskey_test_xxx".to_string(),
        store_id: "12345".to_string(),
        webhook_secret: "ls_test_secret".to_string(),
    };
    let ls_json = serde_json::to_vec(&ls_config).expect("Failed to serialize LS config");
    let ls_encrypted = master_key
        .encrypt_private_key(org_id, &ls_json)
        .expect("Failed to encrypt LS config");

    queries::update_organization_encrypted_configs(
        conn,
        org_id,
        Some(&stripe_encrypted),
        Some(&ls_encrypted),
        None,
    )
    .expect("Failed to set payment configs");
}

/// Create a test license with subscription info (for renewal/cancellation tests)
pub fn create_test_license_with_subscription(
    conn: &Connection,
    project_id: &str,
    product_id: &str,
    expires_at: Option<i64>,
    provider: &str,
    subscription_id: &str,
) -> License {
    let input = CreateLicense {
        email_hash: Some(queries::hash_email("test@example.com")),
        customer_id: Some("test-customer".to_string()),
        expires_at,
        updates_expires_at: expires_at,
        payment_provider: Some(provider.to_string()),
        payment_provider_customer_id: Some("cust_test".to_string()),
        payment_provider_subscription_id: Some(subscription_id.to_string()),
        payment_provider_order_id: Some("order_test".to_string()),
    };
    queries::create_license(conn, project_id, product_id, &input)
        .expect("Failed to create test license with subscription")
}

/// Create a test activation code for a license
pub fn create_test_activation_code(
    conn: &Connection,
    license_id: &str,
    prefix: &str,
) -> ActivationCode {
    queries::create_activation_code(conn, license_id, prefix)
        .expect("Failed to create test activation code")
}
