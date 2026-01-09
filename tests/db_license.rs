//! Database license operation tests

mod common;

use common::*;

// ============ License Creation Tests ============

#[test]
fn test_create_license() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(365)),
    );

    assert!(!license.id.is_empty());
    assert!(license.email_hash.is_some()); // Email hash should be set
    assert_eq!(license.product_id, product.id);
    assert_eq!(license.project_id, project.id);
    assert_eq!(license.activation_count, 0);
    assert!(!license.revoked);
    assert!(license.revoked_jtis.is_empty());
}

#[test]
fn test_create_license_with_customer_id() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let input = CreateLicense {
        email_hash: Some(queries::hash_email("customer@example.com")),
        customer_id: Some("cust_12345".to_string()),
        expires_at: None,
        updates_expires_at: None,
        payment_provider: None,
        payment_provider_customer_id: None,
        payment_provider_subscription_id: None,
        payment_provider_order_id: None,
    };

    let license = queries::create_license(&conn, &project.id, &product.id, &input)
        .expect("Failed to create license");

    assert_eq!(license.customer_id, Some("cust_12345".to_string()));
}

#[test]
fn test_create_license_with_payment_provider() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let input = CreateLicense {
        email_hash: Some(queries::hash_email("customer@example.com")),
        customer_id: None,
        expires_at: Some(future_timestamp(30)),
        updates_expires_at: Some(future_timestamp(365)),
        payment_provider: Some("stripe".to_string()),
        payment_provider_customer_id: Some("cus_xxx".to_string()),
        payment_provider_subscription_id: Some("sub_yyy".to_string()),
        payment_provider_order_id: Some("cs_test_xxx".to_string()),
    };

    let license = queries::create_license(&conn, &project.id, &product.id, &input)
        .expect("Failed to create license");

    assert_eq!(license.payment_provider, Some("stripe".to_string()));
    assert_eq!(
        license.payment_provider_customer_id,
        Some("cus_xxx".to_string())
    );
    assert_eq!(
        license.payment_provider_subscription_id,
        Some("sub_yyy".to_string())
    );
}

// ============ License Lookup Tests ============

#[test]
fn test_get_license_by_id() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let created = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(365)),
    );

    let fetched = queries::get_license_by_id(&conn, &created.id)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.product_id, created.product_id);
}

#[test]
fn test_get_license_by_email_hash() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let email = "unique@example.com";
    let email_hash = queries::hash_email(email);

    let input = CreateLicense {
        email_hash: Some(email_hash.clone()),
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
        payment_provider: None,
        payment_provider_customer_id: None,
        payment_provider_subscription_id: None,
        payment_provider_order_id: None,
    };

    let created = queries::create_license(&conn, &project.id, &product.id, &input)
        .expect("Failed to create license");

    let fetched = queries::get_license_by_email_hash(&conn, &project.id, &email_hash)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(fetched.id, created.id);
}

#[test]
fn test_get_license_by_subscription() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let input = CreateLicense {
        email_hash: Some(queries::hash_email("subscriber@example.com")),
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
        payment_provider: Some("stripe".to_string()),
        payment_provider_customer_id: Some("cus_xxx".to_string()),
        payment_provider_subscription_id: Some("sub_unique_id".to_string()),
        payment_provider_order_id: None,
    };

    let created = queries::create_license(&conn, &project.id, &product.id, &input)
        .expect("Failed to create license");

    let fetched = queries::get_license_by_subscription(&conn, "stripe", "sub_unique_id")
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(fetched.id, created.id);
}

#[test]
fn test_get_license_by_subscription_wrong_provider() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let input = CreateLicense {
        email_hash: Some(queries::hash_email("subscriber@example.com")),
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
        payment_provider: Some("stripe".to_string()),
        payment_provider_customer_id: None,
        payment_provider_subscription_id: Some("sub_id".to_string()),
        payment_provider_order_id: None,
    };

    queries::create_license(&conn, &project.id, &product.id, &input)
        .expect("Failed to create license");

    // Same subscription ID but different provider should return None
    let result = queries::get_license_by_subscription(&conn, "lemonsqueezy", "sub_id")
        .expect("Query failed");

    assert!(result.is_none());
}

#[test]
fn test_list_licenses_for_project() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product1 = create_test_product(&conn, &project.id, "Free", "free");
    let product2 = create_test_product(&conn, &project.id, "Pro", "pro");

    // Create licenses for both products
    create_test_license(&conn, &project.id, &product1.id, None);
    create_test_license(&conn, &project.id, &product1.id, None);
    create_test_license(&conn, &project.id, &product2.id, None);

    let licenses = queries::list_licenses_for_project(&conn, &project.id)
        .expect("Query failed");

    assert_eq!(licenses.len(), 3);
    // Verify the product name is included
    assert!(licenses.iter().any(|l| l.product_name == "Free"));
    assert!(licenses.iter().any(|l| l.product_name == "Pro"));
}

// ============ License Operations Tests ============

#[test]
fn test_increment_activation_count() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    assert_eq!(license.activation_count, 0);

    queries::increment_activation_count(&conn, &license.id).expect("Increment failed");
    queries::increment_activation_count(&conn, &license.id).expect("Increment failed");
    queries::increment_activation_count(&conn, &license.id).expect("Increment failed");

    let updated = queries::get_license_by_id(&conn, &license.id)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(updated.activation_count, 3);
}

#[test]
fn test_revoke_license() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    assert!(!license.revoked);

    queries::revoke_license(&conn, &license.id).expect("Revoke failed");

    let revoked = queries::get_license_by_id(&conn, &license.id)
        .expect("Query failed")
        .expect("License not found");

    assert!(revoked.revoked);
}

#[test]
fn test_add_revoked_jti() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    assert!(license.revoked_jtis.is_empty());

    queries::add_revoked_jti(&conn, &license.id, "jti_1").expect("Add JTI failed");
    queries::add_revoked_jti(&conn, &license.id, "jti_2").expect("Add JTI failed");

    let updated = queries::get_license_by_id(&conn, &license.id)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(updated.revoked_jtis.len(), 2);
    assert!(updated.revoked_jtis.contains(&"jti_1".to_string()));
    assert!(updated.revoked_jtis.contains(&"jti_2".to_string()));
}

#[test]
fn test_extend_license_expiration() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let old_exp = future_timestamp(30);
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(old_exp),
    );

    let new_exp = future_timestamp(365);
    queries::extend_license_expiration(&conn, &license.id, Some(new_exp), Some(new_exp))
        .expect("Extend failed");

    let updated = queries::get_license_by_id(&conn, &license.id)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(updated.expires_at, Some(new_exp));
    assert_eq!(updated.updates_expires_at, Some(new_exp));
}

// ============ Activation Code Tests ============

#[test]
fn test_create_activation_code() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    let code = queries::create_activation_code(&conn, &license.id, "TEST")
        .expect("Failed to create activation code");

    assert!(!code.id.is_empty());
    assert!(code.code.starts_with("TEST-")); // PREFIX-XXXX-XXXX-XXXX-XXXX format
    assert_eq!(code.license_id, license.id);
    assert!(!code.used);
    assert!(code.expires_at > now()); // Expires in the future
}

#[test]
fn test_activation_code_format() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    let code = queries::create_activation_code(&conn, &license.id, "MYAPP")
        .expect("Failed to create activation code");

    // Format should be PREFIX-XXXX-XXXX-XXXX-XXXX
    assert!(code.code.starts_with("MYAPP-"));
    let parts: Vec<&str> = code.code.split('-').collect();
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[0], "MYAPP");
    for part in &parts[1..] {
        assert_eq!(part.len(), 4);
    }
}

#[test]
fn test_get_activation_code_by_code() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);
    let created = queries::create_activation_code(&conn, &license.id, "TEST")
        .expect("Failed to create activation code");

    let fetched = queries::get_activation_code_by_code(&conn, &created.code)
        .expect("Query failed")
        .expect("Code not found");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.license_id, license.id);
}

#[test]
fn test_mark_activation_code_used() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);
    let code = queries::create_activation_code(&conn, &license.id, "TEST")
        .expect("Failed to create activation code");

    assert!(!code.used);

    queries::mark_activation_code_used(&conn, &code.id).expect("Mark used failed");

    let updated = queries::get_activation_code_by_code(&conn, &code.code)
        .expect("Query failed")
        .expect("Code not found");

    assert!(updated.used);
}

// ============ Email Hash Tests ============

#[test]
fn test_email_hash_consistency() {
    // Same email should always produce the same hash
    let hash1 = queries::hash_email("test@example.com");
    let hash2 = queries::hash_email("test@example.com");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_email_hash_case_insensitive() {
    // Email hashing should be case-insensitive
    let hash1 = queries::hash_email("Test@Example.COM");
    let hash2 = queries::hash_email("test@example.com");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_email_hash_trims_whitespace() {
    // Email hashing should trim whitespace
    let hash1 = queries::hash_email("  test@example.com  ");
    let hash2 = queries::hash_email("test@example.com");
    assert_eq!(hash1, hash2);
}

// ============ License Expiration Tests ============

#[test]
fn test_license_with_expiration() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let exp = future_timestamp(365);
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(exp),
    );

    assert_eq!(license.expires_at, Some(exp));
}

#[test]
fn test_license_without_expiration() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let license = create_test_license(&conn, &project.id, &product.id, None);

    assert!(license.expires_at.is_none()); // Perpetual license
}

// ============ Cascade Delete Tests ============

#[test]
fn test_delete_product_cascades_to_licenses() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    queries::delete_product(&conn, &product.id).expect("Delete failed");

    let result = queries::get_license_by_id(&conn, &license.id).expect("Query failed");
    assert!(result.is_none());
}

#[test]
fn test_delete_license_cascades_to_activation_codes() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);
    let code = queries::create_activation_code(&conn, &license.id, "TEST")
        .expect("Failed to create activation code");

    // Delete the product (which cascades to licenses, which cascades to codes)
    queries::delete_product(&conn, &product.id).expect("Delete failed");

    let result = queries::get_activation_code_by_code(&conn, &code.code).expect("Query failed");
    assert!(result.is_none());
}
