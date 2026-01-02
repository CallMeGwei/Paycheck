//! Database license operation tests

mod common;

use common::*;

// ============ License Key Creation Tests ============

#[test]
fn test_create_license_key() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let license = create_test_license(&conn, &project.id, &product.id, "TEST", Some(future_timestamp(365)), &master_key);

    assert!(!license.id.is_empty());
    assert!(license.key.starts_with("TEST-"));
    assert_eq!(license.product_id, product.id);
    assert_eq!(license.project_id, project.id);
    assert_eq!(license.activation_count, 0);
    assert!(!license.revoked);
    assert!(license.revoked_jtis.is_empty());
}

#[test]
fn test_license_key_format() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    // Create a few licenses to verify format is consistent
    for _ in 0..5 {
        let license = create_test_license(&conn, &project.id, &product.id, "MYAPP", None, &master_key);

        // Format should be PREFIX-XXXX-XXXX-XXXX-XXXX
        assert!(license.key.starts_with("MYAPP-"));
        let parts: Vec<&str> = license.key.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "MYAPP");
        for part in &parts[1..] {
            assert_eq!(part.len(), 4);
        }
    }
}

#[test]
fn test_license_key_uniqueness() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    // Create many licenses and verify they're all unique
    let mut keys = std::collections::HashSet::new();
    for _ in 0..100 {
        let license = create_test_license(&conn, &project.id, &product.id, "TEST", None, &master_key);
        assert!(keys.insert(license.key), "Duplicate license key generated");
    }
}

#[test]
fn test_create_license_with_customer_id() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let input = CreateLicenseKey {
        customer_id: Some("cust_12345".to_string()),
        expires_at: None,
        updates_expires_at: None,
        payment_provider: None,
        payment_provider_customer_id: None,
        payment_provider_subscription_id: None,
        payment_provider_order_id: None,
    };

    let license = queries::create_license_key(&conn, &project.id, &product.id, "TEST", &input, &master_key)
        .expect("Failed to create license");

    assert_eq!(license.customer_id, Some("cust_12345".to_string()));
}

#[test]
fn test_create_license_with_payment_provider() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let input = CreateLicenseKey {
        customer_id: None,
        expires_at: Some(future_timestamp(30)),
        updates_expires_at: Some(future_timestamp(365)),
        payment_provider: Some("stripe".to_string()),
        payment_provider_customer_id: Some("cus_xxx".to_string()),
        payment_provider_subscription_id: Some("sub_yyy".to_string()),
        payment_provider_order_id: Some("cs_test_xxx".to_string()),
    };

    let license = queries::create_license_key(&conn, &project.id, &product.id, "TEST", &input, &master_key)
        .expect("Failed to create license");

    assert_eq!(license.payment_provider, Some("stripe".to_string()));
    assert_eq!(license.payment_provider_customer_id, Some("cus_xxx".to_string()));
    assert_eq!(license.payment_provider_subscription_id, Some("sub_yyy".to_string()));
}

// ============ License Key Lookup Tests ============

#[test]
fn test_get_license_key_by_id() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let created = create_test_license(&conn, &project.id, &product.id, "TEST", Some(future_timestamp(365)), &master_key);

    let fetched = queries::get_license_key_by_id(&conn, &created.id, &master_key)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.key, created.key);
    assert_eq!(fetched.product_id, created.product_id);
}

#[test]
fn test_get_license_key_by_key() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let created = create_test_license(&conn, &project.id, &product.id, "TEST", Some(future_timestamp(365)), &master_key);

    let fetched = queries::get_license_key_by_key(&conn, &created.key, &master_key)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.key, created.key);
}

#[test]
fn test_get_license_key_by_subscription() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let input = CreateLicenseKey {
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
        payment_provider: Some("stripe".to_string()),
        payment_provider_customer_id: Some("cus_xxx".to_string()),
        payment_provider_subscription_id: Some("sub_unique_id".to_string()),
        payment_provider_order_id: None,
    };

    let created = queries::create_license_key(&conn, &project.id, &product.id, "TEST", &input, &master_key)
        .expect("Failed to create license");

    let fetched = queries::get_license_key_by_subscription(&conn, "stripe", "sub_unique_id", &master_key)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(fetched.id, created.id);
}

#[test]
fn test_get_license_key_by_subscription_wrong_provider() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let input = CreateLicenseKey {
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
        payment_provider: Some("stripe".to_string()),
        payment_provider_customer_id: None,
        payment_provider_subscription_id: Some("sub_id".to_string()),
        payment_provider_order_id: None,
    };

    queries::create_license_key(&conn, &project.id, &product.id, "TEST", &input, &master_key)
        .expect("Failed to create license");

    // Same subscription ID but different provider should return None
    let result = queries::get_license_key_by_subscription(&conn, "lemonsqueezy", "sub_id", &master_key)
        .expect("Query failed");

    assert!(result.is_none());
}

#[test]
fn test_list_license_keys_for_project() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product1 = create_test_product(&conn, &project.id, "Free", "free");
    let product2 = create_test_product(&conn, &project.id, "Pro", "pro");

    // Create licenses for both products
    create_test_license(&conn, &project.id, &product1.id, "TEST", None, &master_key);
    create_test_license(&conn, &project.id, &product1.id, "TEST", None, &master_key);
    create_test_license(&conn, &project.id, &product2.id, "TEST", None, &master_key);

    let licenses = queries::list_license_keys_for_project(&conn, &project.id, &master_key)
        .expect("Query failed");

    assert_eq!(licenses.len(), 3);
    // Verify the product name is included
    assert!(licenses.iter().any(|l| l.product_name == "Free"));
    assert!(licenses.iter().any(|l| l.product_name == "Pro"));
}

// ============ License Key Operations Tests ============

#[test]
fn test_increment_activation_count() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, "TEST", None, &master_key);

    assert_eq!(license.activation_count, 0);

    queries::increment_activation_count(&conn, &license.id).expect("Increment failed");
    queries::increment_activation_count(&conn, &license.id).expect("Increment failed");
    queries::increment_activation_count(&conn, &license.id).expect("Increment failed");

    let updated = queries::get_license_key_by_id(&conn, &license.id, &master_key)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(updated.activation_count, 3);
}

#[test]
fn test_revoke_license_key() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, "TEST", None, &master_key);

    assert!(!license.revoked);

    queries::revoke_license_key(&conn, &license.id).expect("Revoke failed");

    let revoked = queries::get_license_key_by_id(&conn, &license.id, &master_key)
        .expect("Query failed")
        .expect("License not found");

    assert!(revoked.revoked);
}

#[test]
fn test_add_revoked_jti() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, "TEST", None, &master_key);

    assert!(license.revoked_jtis.is_empty());

    queries::add_revoked_jti(&conn, &license.id, "jti_1", &master_key).expect("Add JTI failed");
    queries::add_revoked_jti(&conn, &license.id, "jti_2", &master_key).expect("Add JTI failed");

    let updated = queries::get_license_key_by_id(&conn, &license.id, &master_key)
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
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let old_exp = future_timestamp(30);
    let license = create_test_license(&conn, &project.id, &product.id, "TEST", Some(old_exp), &master_key);

    let new_exp = future_timestamp(365);
    queries::extend_license_expiration(&conn, &license.id, Some(new_exp), Some(new_exp))
        .expect("Extend failed");

    let updated = queries::get_license_key_by_id(&conn, &license.id, &master_key)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(updated.expires_at, Some(new_exp));
    assert_eq!(updated.updates_expires_at, Some(new_exp));
}

// ============ Redemption Code Tests ============

#[test]
fn test_create_redemption_code() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, "TEST", None, &master_key);

    let code = queries::create_redemption_code(&conn, &license.id)
        .expect("Failed to create redemption code");

    assert!(!code.id.is_empty());
    assert!(!code.code.is_empty());
    assert_eq!(code.code.len(), 16); // 16 character code
    assert_eq!(code.license_key_id, license.id);
    assert!(!code.used);
    assert!(code.expires_at > now()); // Expires in the future
}

#[test]
fn test_get_redemption_code_by_code() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, "TEST", None, &master_key);
    let created = queries::create_redemption_code(&conn, &license.id)
        .expect("Failed to create redemption code");

    let fetched = queries::get_redemption_code_by_code(&conn, &created.code)
        .expect("Query failed")
        .expect("Code not found");

    assert_eq!(fetched.id, created.id);
    // Note: fetched.code contains the hash, not plaintext (code is hashed at rest)
    assert_eq!(fetched.license_key_id, license.id);
}

#[test]
fn test_mark_redemption_code_used() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, "TEST", None, &master_key);
    let code = queries::create_redemption_code(&conn, &license.id)
        .expect("Failed to create redemption code");

    assert!(!code.used);

    queries::mark_redemption_code_used(&conn, &code.id).expect("Mark used failed");

    let updated = queries::get_redemption_code_by_code(&conn, &code.code)
        .expect("Query failed")
        .expect("Code not found");

    assert!(updated.used);
}

// ============ License Expiration Tests ============

#[test]
fn test_license_with_expiration() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let exp = future_timestamp(365);
    let license = create_test_license(&conn, &project.id, &product.id, "TEST", Some(exp), &master_key);

    assert_eq!(license.expires_at, Some(exp));
}

#[test]
fn test_license_without_expiration() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let license = create_test_license(&conn, &project.id, &product.id, "TEST", None, &master_key);

    assert!(license.expires_at.is_none()); // Perpetual license
}

// ============ Cascade Delete Tests ============

#[test]
fn test_delete_product_cascades_to_licenses() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, "TEST", None, &master_key);

    queries::delete_product(&conn, &product.id).expect("Delete failed");

    let result = queries::get_license_key_by_id(&conn, &license.id, &master_key).expect("Query failed");
    assert!(result.is_none());
}

#[test]
fn test_delete_license_cascades_to_redemption_codes() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App");
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, "TEST", None, &master_key);
    let code = queries::create_redemption_code(&conn, &license.id)
        .expect("Failed to create redemption code");

    // Delete the product (which cascades to licenses, which cascades to codes)
    queries::delete_product(&conn, &product.id).expect("Delete failed");

    let result = queries::get_redemption_code_by_code(&conn, &code.code).expect("Query failed");
    assert!(result.is_none());
}
