//! Test utilities and fixtures for Paycheck integration tests

#![allow(dead_code)]

use axum::Router;

// ============ Time Constants ============
// Use these with future_timestamp() and past_timestamp() for readable tests

/// One year in days (365)
pub const ONE_YEAR: i64 = 365;
/// One month in days (30)
pub const ONE_MONTH: i64 = 30;
/// One week in days (7)
pub const ONE_WEEK: i64 = 7;
/// One day
pub const ONE_DAY: i64 = 1;
/// One hour in days (for sub-day precision, use directly with timestamp math)
pub const ONE_HOUR_SECS: i64 = 3600;

// Semantic aliases for common test scenarios
/// License validity period for standard tests
pub const LICENSE_VALID_DAYS: i64 = 365;
/// Short expiry for edge case tests
pub const EXPIRES_SOON_DAYS: i64 = 1;
/// Updates validity period
pub const UPDATES_VALID_DAYS: i64 = 180;
use axum::routing::{get, post};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use std::sync::Arc;

// Re-export the main library crate
pub use paycheck::crypto::{EmailHasher, MasterKey};
pub use paycheck::db::{AppState, init_audit_db, init_db, queries};
pub use paycheck::email::EmailService;
pub use paycheck::handlers::public::{
    deactivate_device, get_license_info, initiate_buy, payment_callback, redeem_with_code,
    request_activation_code, validate_license,
};
pub use paycheck::jwt::{self, JwksCache};
pub use paycheck::models::*;
pub use paycheck::rate_limit::ActivationRateLimiter;

/// Create a test master key (deterministic for testing)
pub fn test_master_key() -> MasterKey {
    // Use a fixed test key (32 bytes of zeros - ONLY for testing!)
    MasterKey::from_bytes([0u8; 32])
}

/// Create a test email hasher (deterministic for testing)
pub fn test_email_hasher() -> EmailHasher {
    // Use a fixed test key (32 bytes of 0xAA - ONLY for testing!)
    // Different from master key to ensure they're independent
    EmailHasher::from_bytes([0xAA; 32])
}

/// Create an in-memory test database with schema initialized
pub fn setup_test_db() -> Connection {
    let conn = Connection::open_in_memory().expect("Failed to create in-memory database");
    init_db(&conn).expect("Failed to initialize schema");
    conn
}

/// Create an in-memory test audit database with schema initialized
pub fn setup_test_audit_db() -> Connection {
    let conn = Connection::open_in_memory().expect("Failed to create in-memory audit database");
    init_audit_db(&conn).expect("Failed to initialize audit schema");
    conn
}

/// Create a test user
pub fn create_test_user(conn: &Connection, email: &str, name: &str) -> User {
    let input = CreateUser {
        email: email.to_string(),
        name: name.to_string(),
    };
    queries::create_user(conn, &input).expect("Failed to create test user")
}

/// Create a test operator with default values (returns User, Operator, and API key)
pub fn create_test_operator(
    conn: &Connection,
    email: &str,
    role: OperatorRole,
) -> (User, Operator, String) {
    // Create user first
    let user = create_test_user(conn, email, &format!("Test Operator {}", email));

    // Create operator linked to user
    let input = CreateOperator {
        user_id: user.id.clone(),
        role,
    };
    let operator = queries::create_operator(conn, &input).expect("Failed to create test operator");

    // Create API key for the user
    let (_, api_key) = queries::create_api_key(conn, &user.id, "Default", None, true, None)
        .expect("Failed to create test operator API key");

    (user, operator, api_key)
}

/// Create a test organization
pub fn create_test_org(conn: &Connection, name: &str) -> Organization {
    let input = CreateOrganization {
        name: name.to_string(),
        owner_user_id: None,
    };
    queries::create_organization(conn, &input).expect("Failed to create test organization")
}

/// Create a test org member with default values (returns User, OrgMember, and API key)
pub fn create_test_org_member(
    conn: &Connection,
    org_id: &str,
    email: &str,
    role: OrgMemberRole,
) -> (User, OrgMember, String) {
    // Create user first
    let user = create_test_user(conn, email, &format!("Test Member {}", email));

    // Create org member linked to user
    let input = CreateOrgMember {
        user_id: user.id.clone(),
        role,
    };
    let member =
        queries::create_org_member(conn, org_id, &input).expect("Failed to create test org member");

    // Create an API key for the user
    let (_, api_key) = queries::create_api_key(conn, &member.user_id, "Default", None, true, None)
        .expect("Failed to create test org member API key");

    (user, member, api_key)
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
        license_key_prefix: "TEST".to_string(),
        redirect_url: None,
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

/// Create a test license (uses master key for secure email hashing)
pub fn create_test_license(
    conn: &Connection,
    project_id: &str,
    product_id: &str,
    expires_at: Option<i64>,
) -> License {
    let input = CreateLicense {
        email_hash: Some(test_email_hasher().hash("test@example.com")),
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
    let email_hasher = test_email_hasher();

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
        email_hasher,
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: Arc::new(ActivationRateLimiter::default()),
        email_service: Arc::new(EmailService::new(None, "test@example.com".to_string())),
        jwks_cache: Arc::new(JwksCache::new()),
        trusted_issuers: vec![],
    }
}

/// Create a Router with all public endpoints (without rate limiting for tests)
pub fn public_app(state: AppState) -> Router {
    Router::new()
        .route("/buy", post(initiate_buy))
        .route("/callback", get(payment_callback))
        .route("/redeem", post(redeem_with_code))
        .route("/activation/request-code", post(request_activation_code))
        .route("/validate", post(validate_license))
        .route("/license", get(get_license_info))
        .route("/devices/deactivate", post(deactivate_device))
        .with_state(state)
}

/// Create a test payment session.
/// Note: Device info is NOT stored in payment sessions - purchase ≠ activation.
/// Redirect URL is configured per-project, not per-session.
pub fn create_test_payment_session(
    conn: &Connection,
    product_id: &str,
    customer_id: Option<&str>,
) -> PaymentSession {
    let input = CreatePaymentSession {
        product_id: product_id.to_string(),
        customer_id: customer_id.map(|s| s.to_string()),
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
        email_hash: Some(test_email_hasher().hash("test@example.com")),
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

// ============ Security Test Utilities ============

/// Create an API key with org-level scope restriction
pub fn create_api_key_with_org_scope(
    conn: &Connection,
    user_id: &str,
    org_id: &str,
    access: AccessLevel,
) -> String {
    let scope = CreateApiKeyScope {
        org_id: org_id.to_string(),
        project_id: None,
        access,
    };
    let (_, raw_key) = queries::create_api_key(conn, user_id, "Scoped", None, true, Some(&[scope]))
        .expect("Failed to create API key with org scope");
    raw_key
}

/// Create an API key with project-level scope restriction
pub fn create_api_key_with_project_scope(
    conn: &Connection,
    user_id: &str,
    org_id: &str,
    project_id: &str,
    access: AccessLevel,
) -> String {
    let scope = CreateApiKeyScope {
        org_id: org_id.to_string(),
        project_id: Some(project_id.to_string()),
        access,
    };
    let (_, raw_key) = queries::create_api_key(conn, user_id, "Scoped", None, true, Some(&[scope]))
        .expect("Failed to create API key with project scope");
    raw_key
}

/// Create an API key that is already expired
pub fn create_expired_api_key(conn: &Connection, user_id: &str) -> String {
    // Pass -1 days to create a key that expired 1 day ago
    // The create_api_key function calculates: expires_at = now + days * 86400
    // So -1 gives us: now - 86400 (1 day in the past)
    let (_, raw_key) = queries::create_api_key(conn, user_id, "Expired", Some(-1), true, None)
        .expect("Failed to create expired API key");
    raw_key
}

/// Create an API key and immediately revoke it
pub fn create_revoked_api_key(conn: &Connection, user_id: &str) -> String {
    let (api_key_record, raw_key) =
        queries::create_api_key(conn, user_id, "Revoked", None, true, None)
            .expect("Failed to create API key");

    queries::revoke_api_key(conn, &api_key_record.id).expect("Failed to revoke API key");

    raw_key
}

/// Create a project member with a specific role
pub fn create_test_project_member(
    conn: &Connection,
    org_member_id: &str,
    project_id: &str,
    role: ProjectMemberRole,
) -> ProjectMember {
    let input = CreateProjectMember {
        org_member_id: org_member_id.to_string(),
        role,
    };
    queries::create_project_member(conn, project_id, &input)
        .expect("Failed to create test project member")
}

/// Generate a malicious input string for SQL injection testing
pub fn sql_injection_payloads() -> Vec<&'static str> {
    vec![
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "1; DELETE FROM licenses WHERE 1=1; --",
        "' UNION SELECT * FROM api_keys --",
        "admin'--",
        "1' AND 1=0 UNION SELECT id, key_hash, 1, 1, 1, 1, 1, 1, 1, 1 FROM api_keys--",
    ]
}

/// Generate path traversal payloads for testing
pub fn path_traversal_payloads() -> Vec<&'static str> {
    vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
    ]
}

/// Generate unicode/encoding attack payloads
pub fn unicode_attack_payloads() -> Vec<&'static str> {
    vec![
        "test\x00admin",     // Null byte
        "test\u{202E}admin", // RTL override
        "tеst",              // Cyrillic 'е' (U+0435)
        "test\u{FEFF}admin", // BOM
        "\u{0000}",          // Null char
    ]
}

/// Sign JWT claims with a custom expiration offset (for testing expired/fresh tokens)
/// `exp_offset_secs` is added to the current time to set the JWT `exp` claim.
/// Use negative values to create already-expired tokens.
pub fn sign_claims_with_exp_offset(
    claims: &jwt::LicenseClaims,
    private_key: &[u8],
    subject: &str,
    audience: &str,
    jti: &str,
    exp_offset_secs: i64,
) -> String {
    use ed25519_dalek::SigningKey;
    use jwt_simple::prelude::*;

    let key_bytes: [u8; 32] = private_key.try_into().expect("Invalid private key length");
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let key_pair = Ed25519KeyPair::from_bytes(&signing_key.to_keypair_bytes())
        .expect("Failed to create key pair");

    // Calculate absolute expiration time
    let exp_time = chrono::Utc::now().timestamp() + exp_offset_secs;

    // Create claims - use a duration and then override the expires_at field
    let mut jwt_claims = Claims::with_custom_claims(claims.clone(), Duration::from_secs(3600))
        .with_issuer("paycheck")
        .with_subject(subject)
        .with_audience(audience)
        .with_jwt_id(jti);

    // Override the expiration time
    jwt_claims.expires_at = Some(UnixTimeStamp::from_secs(exp_time as u64));

    key_pair.sign(jwt_claims).expect("Failed to sign token")
}

/// Create a license at device limit (all slots used)
pub fn create_license_at_device_limit(
    conn: &Connection,
    project_id: &str,
    product: &Product,
) -> (License, Vec<Device>) {
    let license = create_test_license(conn, project_id, &product.id, Some(future_timestamp(365)));

    let mut devices = Vec::new();
    for i in 0..product.device_limit {
        let device = create_test_device(
            conn,
            &license.id,
            &format!("device_{}", i),
            DeviceType::Uuid,
        );
        devices.push(device);
    }

    (license, devices)
}
