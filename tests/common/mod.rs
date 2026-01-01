//! Test utilities and fixtures for Paycheck integration tests

use rusqlite::Connection;

// Re-export the main library crate
pub use paycheck::crypto::MasterKey;
pub use paycheck::db::{init_audit_db, init_db, queries};
pub use paycheck::jwt;
pub use paycheck::models::*;

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

/// Create an in-memory audit database with schema initialized
pub fn setup_audit_db() -> Connection {
    let conn = Connection::open_in_memory().expect("Failed to create in-memory audit database");
    init_audit_db(&conn).expect("Failed to initialize audit schema");
    conn
}

/// Create a test operator with default values
pub fn create_test_operator(conn: &Connection, email: &str, role: OperatorRole) -> (Operator, String) {
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

/// Create a test project with auto-generated keypair
pub fn create_test_project(conn: &Connection, org_id: &str, name: &str) -> Project {
    let input = CreateProject {
        name: name.to_string(),
        domain: format!("{}.example.com", name.to_lowercase().replace(' ', "-")),
        license_key_prefix: "TEST".to_string(),
    };
    let (private_key, public_key) = jwt::generate_keypair();
    queries::create_project(conn, org_id, &input, &private_key, &public_key)
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

/// Create a test license key
pub fn create_test_license(
    conn: &Connection,
    product_id: &str,
    prefix: &str,
    expires_at: Option<i64>,
) -> LicenseKey {
    let input = CreateLicenseKey {
        customer_id: Some("test-customer".to_string()),
        expires_at,
        updates_expires_at: expires_at,
        payment_provider: None,
        payment_provider_customer_id: None,
        payment_provider_subscription_id: None,
        payment_provider_order_id: None,
    };
    queries::create_license_key(conn, product_id, prefix, &input)
        .expect("Failed to create test license")
}

/// Create a test device for a license
pub fn create_test_device(
    conn: &Connection,
    license_key_id: &str,
    device_id: &str,
    device_type: DeviceType,
) -> Device {
    let jti = uuid::Uuid::new_v4().to_string();
    queries::create_device(conn, license_key_id, device_id, device_type, &jti, Some("Test Device"))
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

/// Test data builder for creating complete test hierarchies
pub struct TestDataBuilder {
    pub conn: Connection,
}

impl TestDataBuilder {
    pub fn new() -> Self {
        Self {
            conn: setup_test_db(),
        }
    }

    /// Create a complete test hierarchy: org -> project -> product -> license
    pub fn create_full_hierarchy(&self) -> TestHierarchy {
        let org = create_test_org(&self.conn, "Test Org");
        let (member, member_api_key) =
            create_test_org_member(&self.conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
        let project = create_test_project(&self.conn, &org.id, "Test Project");
        let product = create_test_product(&self.conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(&self.conn, &product.id, &project.license_key_prefix, Some(future_timestamp(365)));

        TestHierarchy {
            org,
            member,
            member_api_key,
            project,
            product,
            license,
        }
    }
}

impl Default for TestDataBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A complete test hierarchy with all related entities
pub struct TestHierarchy {
    pub org: Organization,
    pub member: OrgMember,
    pub member_api_key: String,
    pub project: Project,
    pub product: Product,
    pub license: LicenseKey,
}
