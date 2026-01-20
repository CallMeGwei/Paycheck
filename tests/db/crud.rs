//! Database CRUD operation tests for core entities

#[path = "../common/mod.rs"]
mod common;

use common::*;

// ============ Operator Tests ============

#[test]
fn test_create_operator() {
    let mut conn = setup_test_db();
    let (user, api_key) = create_test_operator(&mut conn, "test@example.com", OperatorRole::Admin);

    assert!(!user.id.is_empty(), "user should have a generated ID");
    assert_eq!(
        user.email, "test@example.com",
        "user email should match input"
    );
    assert_eq!(
        user.operator_role,
        Some(OperatorRole::Admin),
        "operator role should match input"
    );
    assert!(!api_key.is_empty(), "API key should be generated");
    assert!(api_key.starts_with("pc_"), "API key should have pc_ prefix");
}

#[test]
fn test_get_operator_by_user_id() {
    let mut conn = setup_test_db();
    let (created, _) = create_test_operator(&mut conn, "test@example.com", OperatorRole::Owner);

    let fetched = queries::get_user_by_id(&mut conn, &created.id)
        .expect("Query failed")
        .expect("User not found");

    assert_eq!(
        fetched.id, created.id,
        "fetched user ID should match created"
    );
    assert_eq!(
        fetched.operator_role, created.operator_role,
        "fetched operator role should match created"
    );
}

#[test]
fn test_get_user_by_api_key() {
    let mut conn = setup_test_db();
    let (created_user, api_key) =
        create_test_operator(&mut conn, "test@example.com", OperatorRole::View);

    let (fetched_user, _api_key) = queries::get_user_by_api_key(&mut conn, &api_key)
        .expect("Query failed")
        .expect("User not found");

    assert_eq!(
        fetched_user.id, created_user.id,
        "fetched user ID should match created user"
    );
}

#[test]
fn test_get_user_with_invalid_api_key_returns_none() {
    let mut conn = setup_test_db();
    let _ = create_test_operator(&mut conn, "test@example.com", OperatorRole::Admin);

    let result = queries::get_user_by_api_key(&mut conn, "invalid_key").expect("Query failed");

    assert!(result.is_none(), "invalid API key should return None");
}

#[test]
fn test_list_operators() {
    let mut conn = setup_test_db();
    create_test_operator(&mut conn, "test1@example.com", OperatorRole::Owner);
    create_test_operator(&mut conn, "test2@example.com", OperatorRole::Admin);
    create_test_operator(&mut conn, "test3@example.com", OperatorRole::View);

    let operators = queries::list_operators(&conn).expect("Query failed");

    assert_eq!(operators.len(), 3, "should return all 3 created operators");
}

#[test]
fn test_update_operator_role() {
    let mut conn = setup_test_db();
    let (user, _) = create_test_operator(&mut conn, "test@example.com", OperatorRole::View);

    let updated = queries::update_operator_role(&mut conn, &user.id, OperatorRole::Admin)
        .expect("Update failed")
        .expect("Should return updated user");

    assert_eq!(
        updated.operator_role,
        Some(OperatorRole::Admin),
        "operator role should be updated to Admin"
    );
}

#[test]
fn test_revoke_operator_role() {
    let mut conn = setup_test_db();
    let (user, _) = create_test_operator(&mut conn, "test@example.com", OperatorRole::Admin);

    let revoked = queries::revoke_operator_role(&mut conn, &user.id).expect("Revoke failed");
    assert!(revoked, "revoke should return true for existing operator");

    let result = queries::get_user_by_id(&mut conn, &user.id)
        .expect("Query failed")
        .expect("User should still exist");
    assert!(
        result.operator_role.is_none(),
        "operator role should be None after revoke"
    );
}

// ============ Organization Tests ============

#[test]
fn test_create_organization() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "Test Organization");

    assert!(
        !org.id.is_empty(),
        "organization should have a generated ID"
    );
    assert_eq!(
        org.name, "Test Organization",
        "organization name should match input"
    );
    assert!(org.created_at > 0, "created_at should be a valid timestamp");
}

#[test]
fn test_get_organization_by_id() {
    let mut conn = setup_test_db();
    let created = create_test_org(&mut conn, "Test Org");

    let fetched = queries::get_organization_by_id(&mut conn, &created.id)
        .expect("Query failed")
        .expect("Organization not found");

    assert_eq!(
        fetched.id, created.id,
        "fetched org ID should match created"
    );
    assert_eq!(
        fetched.name, created.name,
        "fetched org name should match created"
    );
}

#[test]
fn test_list_organizations() {
    let mut conn = setup_test_db();
    create_test_org(&mut conn, "Org 1");
    create_test_org(&mut conn, "Org 2");

    let orgs = queries::list_organizations(&conn).expect("Query failed");
    assert_eq!(orgs.len(), 2, "should return all 2 created organizations");
}

#[test]
fn test_update_organization() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Original Name");

    let update = UpdateOrganization {
        name: Some("Updated Name".to_string()),
        stripe_config: None,
        ls_config: None,
        resend_api_key: None,
        payment_provider: None,
    };
    queries::update_organization(&conn, &org.id, &update).expect("Update failed");

    let updated = queries::get_organization_by_id(&conn, &org.id)
        .expect("Query failed")
        .expect("Organization not found");

    assert_eq!(
        updated.name, "Updated Name",
        "organization name should be updated"
    );
}

#[test]
fn test_delete_organization() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "To Delete");

    let deleted = queries::delete_organization(&mut conn, &org.id).expect("Delete failed");
    assert!(
        deleted,
        "delete should return true for existing organization"
    );

    let result = queries::get_organization_by_id(&mut conn, &org.id).expect("Query failed");
    assert!(result.is_none(), "deleted organization should not be found");
}

// ============ Org Member Tests ============

#[test]
fn test_create_org_member() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "Test Org");
    let (user, member, api_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Owner);

    assert!(
        !member.id.is_empty(),
        "org member should have a generated ID"
    );
    assert_eq!(member.org_id, org.id, "member org_id should match org");
    assert_eq!(
        user.email, "member@test.com",
        "user email should match input"
    );
    assert_eq!(
        member.role,
        OrgMemberRole::Owner,
        "member role should match input"
    );
    assert!(api_key.starts_with("pc_"), "API key should have pc_ prefix");
}

#[test]
fn test_get_user_by_api_key_for_member() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "Test Org");
    let (created_user, _member, api_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Admin);

    let (fetched_user, _api_key) = queries::get_user_by_api_key(&mut conn, &api_key)
        .expect("Query failed")
        .expect("User not found");

    assert_eq!(
        fetched_user.id, created_user.id,
        "fetched user ID should match org member's user"
    );
}

#[test]
fn test_list_org_members() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "Test Org");
    create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
    create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Admin);
    create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);

    let members = queries::list_org_members(&mut conn, &org.id).expect("Query failed");
    assert_eq!(members.len(), 3, "should return all 3 created org members");
}

#[test]
fn test_same_user_different_orgs() {
    let mut conn = setup_test_db();
    let org1 = create_test_org(&mut conn, "Org 1");
    let org2 = create_test_org(&mut conn, "Org 2");

    // Create first user and member
    let (user1, m1, _) =
        create_test_org_member(&mut conn, &org1.id, "same@test.com", OrgMemberRole::Owner);

    // Same user can be member of another org
    let m2_input = CreateOrgMember {
        user_id: user1.id.clone(),
        role: OrgMemberRole::Owner,
    };
    let m2 = queries::create_org_member(&mut conn, &org2.id, &m2_input)
        .expect("Should allow same user in different org");

    // Same user_id, different orgs
    assert_eq!(
        m1.user_id, m2.user_id,
        "both memberships should reference the same user"
    );
    assert_ne!(
        m1.org_id, m2.org_id,
        "memberships should be in different orgs"
    );
}

// ============ Project Tests ============

#[test]
fn test_create_project() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);

    assert!(!project.id.is_empty(), "project should have a generated ID");
    assert_eq!(project.org_id, org.id, "project org_id should match org");
    assert_eq!(project.name, "My App", "project name should match input");
    assert_eq!(
        project.license_key_prefix, "TEST",
        "project license_key_prefix should match input"
    );
    // Verify keypair was generated
    assert!(
        !project.private_key.is_empty(),
        "project should have a generated private key"
    );
    assert!(
        !project.public_key.is_empty(),
        "project should have a generated public key"
    );
}

#[test]
fn test_get_project_by_id() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let created = create_test_project(&mut conn, &org.id, "My App", &master_key);

    let fetched = queries::get_project_by_id(&mut conn, &created.id)
        .expect("Query failed")
        .expect("Project not found");

    assert_eq!(
        fetched.id, created.id,
        "fetched project ID should match created"
    );
    assert_eq!(
        fetched.name, created.name,
        "fetched project name should match created"
    );
    assert_eq!(
        fetched.public_key, created.public_key,
        "fetched public key should match created"
    );
}

#[test]
fn test_list_projects_for_org() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    create_test_project(&mut conn, &org.id, "App 1", &master_key);
    create_test_project(&mut conn, &org.id, "App 2", &master_key);

    let projects = queries::list_projects_for_org(&mut conn, &org.id).expect("Query failed");
    assert_eq!(
        projects.len(),
        2,
        "should return all 2 projects for the org"
    );
}

#[test]
fn test_update_org_stripe_config() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");

    // Set up Stripe config using the new service config table
    setup_stripe_config(&conn, &org.id, &master_key);

    // Verify config exists
    assert!(
        queries::org_has_service_config(&conn, &org.id, ServiceProvider::Stripe)
            .expect("Query failed"),
        "org should have Stripe config after setup"
    );

    // Verify we can decrypt it
    let decrypted = queries::get_org_stripe_config(&conn, &org.id, &master_key)
        .expect("Query failed")
        .expect("Config not found");
    assert_eq!(
        decrypted.secret_key, "sk_test_abc123xyz789",
        "decrypted secret key should match input"
    );

    // Verify the raw data is actually encrypted (has magic bytes)
    let raw_config = queries::get_org_service_config(&conn, &org.id, ServiceProvider::Stripe)
        .expect("Query failed")
        .expect("Config should exist");
    assert!(
        raw_config.config_encrypted.starts_with(b"ENC1"),
        "config should be encrypted with ENC1 magic bytes"
    );
}

#[test]
fn test_update_org_lemonsqueezy_config() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");

    // Set up LemonSqueezy config using the new service config table
    setup_lemonsqueezy_config(&conn, &org.id, &master_key);

    // Verify config exists
    assert!(
        queries::org_has_service_config(&conn, &org.id, ServiceProvider::LemonSqueezy)
            .expect("Query failed"),
        "org should have LemonSqueezy config after setup"
    );

    // Verify we can decrypt it
    let decrypted = queries::get_org_ls_config(&conn, &org.id, &master_key)
        .expect("Query failed")
        .expect("Config not found");
    assert_eq!(
        decrypted.api_key, "ls_test_key_abcdefghij",
        "decrypted API key should match input"
    );
    assert_eq!(
        decrypted.store_id, "store_123",
        "decrypted store_id should match input"
    );

    // Verify encryption
    let raw_config = queries::get_org_service_config(&conn, &org.id, ServiceProvider::LemonSqueezy)
        .expect("Query failed")
        .expect("Config should exist");
    assert!(
        raw_config.config_encrypted.starts_with(b"ENC1"),
        "config should be encrypted with ENC1 magic bytes"
    );
}

#[test]
fn test_update_org_both_payment_configs() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");

    // Set up both configs using the helper functions
    setup_both_payment_configs(&conn, &org.id, &master_key);

    // Set payment provider
    let update = UpdateOrganization {
        name: None,
        stripe_config: None,
        ls_config: None,
        resend_api_key: None,
        payment_provider: Some(Some("stripe".to_string())),
    };
    queries::update_organization(&conn, &org.id, &update).expect("Update failed");

    // Both configs should be present and decryptable
    assert!(
        queries::org_has_service_config(&conn, &org.id, ServiceProvider::Stripe)
            .expect("Query failed"),
        "org should have Stripe config"
    );
    assert!(
        queries::org_has_service_config(&conn, &org.id, ServiceProvider::LemonSqueezy)
            .expect("Query failed"),
        "org should have LemonSqueezy config"
    );

    let stripe = queries::get_org_stripe_config(&conn, &org.id, &master_key)
        .expect("Stripe query failed")
        .expect("Stripe config not found");
    assert_eq!(
        stripe.secret_key, "sk_test_abc123xyz789",
        "Stripe secret key should match input"
    );

    let ls = queries::get_org_ls_config(&conn, &org.id, &master_key)
        .expect("LS query failed")
        .expect("LS config not found");
    assert_eq!(
        ls.api_key, "ls_test_key_abcdefghij",
        "LemonSqueezy API key should match input"
    );

    let updated = queries::get_organization_by_id(&conn, &org.id)
        .expect("Query failed")
        .expect("Organization not found");
    assert_eq!(
        updated.payment_provider,
        Some("stripe".to_string()),
        "payment_provider should be set to stripe"
    );
}

#[test]
fn test_payment_config_wrong_key_fails() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let wrong_key = MasterKey::from_bytes([1u8; 32]); // Different key
    let org = create_test_org(&conn, "Test Org");

    // Set up Stripe config using the correct key
    setup_stripe_config(&conn, &org.id, &master_key);

    // Decryption with wrong key should fail
    let result = queries::get_org_stripe_config(&conn, &org.id, &wrong_key);
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

// ============ Product Tests ============

#[test]
fn test_create_product() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    assert!(!product.id.is_empty(), "product should have a generated ID");
    assert_eq!(
        product.project_id, project.id,
        "product project_id should match project"
    );
    assert_eq!(product.name, "Pro Plan", "product name should match input");
    assert_eq!(product.tier, "pro", "product tier should match input");
    assert_eq!(
        product.license_exp_days,
        Some(ONE_YEAR as i32),
        "license_exp_days should be 1 year"
    );
    assert_eq!(
        product.device_limit, Some(3),
        "device_limit should match test default"
    );
    assert_eq!(
        product.activation_limit, Some(5),
        "activation_limit should match test default"
    );
    assert_eq!(
        product.features,
        vec!["feature1", "feature2"],
        "features should match test defaults"
    );
}

#[test]
fn test_get_product_by_id() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let created = create_test_product(&mut conn, &project.id, "Enterprise", "enterprise");

    let fetched = queries::get_product_by_id(&mut conn, &created.id)
        .expect("Query failed")
        .expect("Product not found");

    assert_eq!(
        fetched.id, created.id,
        "fetched product ID should match created"
    );
    assert_eq!(
        fetched.tier, "enterprise",
        "fetched product tier should match created"
    );
}

#[test]
fn test_list_products_for_project() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    create_test_product(&mut conn, &project.id, "Free", "free");
    create_test_product(&mut conn, &project.id, "Pro", "pro");
    create_test_product(&mut conn, &project.id, "Enterprise", "enterprise");

    let products = queries::list_products_for_project(&mut conn, &project.id).expect("Query failed");
    assert_eq!(
        products.len(),
        3,
        "should return all 3 products for the project"
    );
}

#[test]
fn test_update_product() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Basic", "basic");

    let update = UpdateProduct {
        name: Some("Premium".to_string()),
        tier: Some("premium".to_string()),
        price_cents: None,
        currency: None,
        license_exp_days: Some(Some(2 * ONE_YEAR as i32)),
        updates_exp_days: None,
        activation_limit: Some(Some(10)),
        device_limit: Some(Some(5)),
        device_inactive_days: None,
        features: Some(vec![
            "feature1".to_string(),
            "feature2".to_string(),
            "feature3".to_string(),
        ]),
    };

    queries::update_product(&mut conn, &product.id, &update).expect("Update failed");

    let updated = queries::get_product_by_id(&mut conn, &product.id)
        .expect("Query failed")
        .expect("Product not found");

    assert_eq!(updated.name, "Premium", "product name should be updated");
    assert_eq!(updated.tier, "premium", "product tier should be updated");
    assert_eq!(
        updated.license_exp_days,
        Some(2 * ONE_YEAR as i32),
        "license_exp_days should be 2 years"
    );
    assert_eq!(
        updated.activation_limit, Some(10),
        "activation_limit should be updated"
    );
    assert_eq!(updated.device_limit, Some(5), "device_limit should be updated");
    assert_eq!(
        updated.features.len(),
        3,
        "features should have 3 items after update"
    );

    // Test updating to None (unlimited) - this is the Some(None) pattern
    let update_to_unlimited = UpdateProduct {
        name: None,
        tier: None,
        price_cents: None,
        currency: None,
        license_exp_days: None,
        updates_exp_days: None,
        activation_limit: Some(None), // Set to unlimited
        device_limit: Some(None),     // Set to unlimited
        device_inactive_days: None,
        features: None,
    };

    queries::update_product(&mut conn, &product.id, &update_to_unlimited).expect("Update to unlimited failed");

    let unlimited = queries::get_product_by_id(&mut conn, &product.id)
        .expect("Query failed")
        .expect("Product not found");

    assert_eq!(
        unlimited.activation_limit, None,
        "activation_limit should be None (unlimited) after update"
    );
    assert_eq!(
        unlimited.device_limit, None,
        "device_limit should be None (unlimited) after update"
    );
    // Verify other fields were NOT changed (outer None = skip update)
    assert_eq!(unlimited.name, "Premium", "name should be unchanged");

    // Test updating device_inactive_days, price_cents, and currency to None
    // First, set device_inactive_days to a value
    let set_inactive_days = UpdateProduct {
        name: None,
        tier: None,
        price_cents: None,
        currency: None,
        license_exp_days: None,
        updates_exp_days: None,
        activation_limit: None,
        device_limit: None,
        device_inactive_days: Some(Some(30)), // Set to 30 days
        features: None,
    };
    queries::update_product(&mut conn, &product.id, &set_inactive_days)
        .expect("Setting device_inactive_days failed");

    let with_inactive = queries::get_product_by_id(&mut conn, &product.id)
        .expect("Query failed")
        .expect("Product not found");
    assert_eq!(
        with_inactive.device_inactive_days, Some(30),
        "device_inactive_days should be 30"
    );

    // Now test updating all three nullable fields to None using Some(None)
    let clear_nullable_fields = UpdateProduct {
        name: None,
        tier: None,
        price_cents: Some(None),        // Clear price
        currency: Some(None),           // Clear currency
        license_exp_days: None,
        updates_exp_days: None,
        activation_limit: None,
        device_limit: None,
        device_inactive_days: Some(None), // Clear device_inactive_days
        features: None,
    };
    queries::update_product(&mut conn, &product.id, &clear_nullable_fields)
        .expect("Clearing nullable fields failed");

    let cleared = queries::get_product_by_id(&mut conn, &product.id)
        .expect("Query failed")
        .expect("Product not found");

    assert_eq!(
        cleared.device_inactive_days, None,
        "device_inactive_days should be None after Some(None) update"
    );
    assert_eq!(
        cleared.price_cents, None,
        "price_cents should be None after Some(None) update"
    );
    assert_eq!(
        cleared.currency, None,
        "currency should be None after Some(None) update"
    );
    // Verify name was NOT changed
    assert_eq!(cleared.name, "Premium", "name should still be unchanged");
}

#[test]
fn test_delete_product() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "To Delete", "delete");

    let deleted = queries::delete_product(&mut conn, &product.id).expect("Delete failed");
    assert!(deleted, "delete should return true for existing product");

    let result = queries::get_product_by_id(&mut conn, &product.id).expect("Query failed");
    assert!(result.is_none(), "deleted product should not be found");
}

// ============ Cascade Delete Tests ============

#[test]
fn test_delete_org_cascades_to_members() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "Test Org");
    let (_user, member, _) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Owner);

    queries::delete_organization(&mut conn, &org.id).expect("Delete failed");

    let result = queries::get_org_member_by_id(&mut conn, &member.id).expect("Query failed");
    assert!(
        result.is_none(),
        "org member should be cascade deleted with org"
    );
}

#[test]
fn test_delete_org_cascades_to_projects() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);

    queries::delete_organization(&mut conn, &org.id).expect("Delete failed");

    let result = queries::get_project_by_id(&mut conn, &project.id).expect("Query failed");
    assert!(
        result.is_none(),
        "project should be cascade deleted with org"
    );
}

#[test]
fn test_delete_project_cascades_to_products() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    queries::delete_project(&mut conn, &project.id).expect("Delete failed");

    let result = queries::get_product_by_id(&mut conn, &product.id).expect("Query failed");
    assert!(
        result.is_none(),
        "product should be cascade deleted with project"
    );
}

// ============ Audit Log Purge Tests ============

#[test]
fn test_purge_old_public_audit_logs_only_deletes_public() {
    let mut conn = setup_test_audit_db();

    // Create audit logs with different actor types, all with old timestamps
    // Using timestamp 0 (1970) to ensure they're "old"
    let old_timestamp = 0i64;

    // Insert logs directly to control timestamp
    conn.execute(
        "INSERT INTO audit_logs (id, timestamp, actor_type, action, resource_type, resource_id)
         VALUES ('log_public', ?1, 'public', 'redeem', 'license', 'lic1')",
        [old_timestamp],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO audit_logs (id, timestamp, actor_type, action, resource_type, resource_id)
         VALUES ('log_internal', ?1, 'user', 'create', 'organization', 'org1')",
        [old_timestamp],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO audit_logs (id, timestamp, actor_type, action, resource_type, resource_id)
         VALUES ('log_user', ?1, 'user', 'create', 'license', 'lic2')",
        [old_timestamp],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO audit_logs (id, timestamp, actor_type, action, resource_type, resource_id)
         VALUES ('log_system', ?1, 'system', 'bootstrap', 'operator', 'op1')",
        [old_timestamp],
    )
    .unwrap();

    // Verify all 4 logs exist
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM audit_logs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 4, "should have 4 audit logs before purge");

    // Purge with 1 day retention (anything older than 1 day ago)
    let deleted = queries::purge_old_public_audit_logs(&mut conn, ONE_DAY).unwrap();

    // Only the public log should be deleted
    assert_eq!(deleted, 1, "should delete only 1 public audit log");

    // Verify only 3 logs remain
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM audit_logs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 3, "should have 3 audit logs after purge");

    // Verify the public log is gone
    let public_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM audit_logs WHERE id = 'log_public')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!public_exists, "public audit log should be deleted");

    // Verify internal logs still exist
    let internal_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM audit_logs WHERE id = 'log_internal')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(internal_exists, "internal audit log should be preserved");

    let user_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM audit_logs WHERE id = 'log_user')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(user_exists, "user audit log should be preserved");

    let system_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM audit_logs WHERE id = 'log_system')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(system_exists, "system audit log should be preserved");
}

#[test]
fn test_purge_old_public_audit_logs_respects_retention_period() {
    let mut conn = setup_test_audit_db();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Create an old public log (100 days old)
    let old_timestamp = now - (100 * 86400);
    conn.execute(
        "INSERT INTO audit_logs (id, timestamp, actor_type, action, resource_type, resource_id)
         VALUES ('log_old_public', ?1, 'public', 'redeem', 'license', 'lic1')",
        [old_timestamp],
    )
    .unwrap();

    // Create a recent public log (1 day old)
    let recent_timestamp = now - (ONE_DAY * 86400);
    conn.execute(
        "INSERT INTO audit_logs (id, timestamp, actor_type, action, resource_type, resource_id)
         VALUES ('log_recent_public', ?1, 'public', 'redeem', 'license', 'lic2')",
        [recent_timestamp],
    )
    .unwrap();

    // Purge with 30 day retention
    let deleted = queries::purge_old_public_audit_logs(&mut conn, ONE_MONTH).unwrap();

    // Only the old public log should be deleted
    assert_eq!(deleted, 1, "should delete only the old public log");

    // Verify the recent public log still exists
    let recent_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM audit_logs WHERE id = 'log_recent_public')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        recent_exists,
        "recent public log within retention period should be preserved"
    );
}

// ============ API Key Scope Validation Tests ============

#[test]
fn test_api_key_scope_rejects_project_from_different_org() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();

    // Create two different orgs
    let org_a = create_test_org(&mut conn, "Org A");
    let org_b = create_test_org(&mut conn, "Org B");

    // Create a project in Org B
    let project_b = create_test_project(&mut conn, &org_b.id, "Project B", &master_key);

    // Create a user who is member of org_a (so membership check passes)
    let (user, _, _) =
        create_test_org_member(&mut conn, &org_a.id, "test@example.com", OrgMemberRole::Member);

    // Try to create an API key with a scope that references org_a but project from org_b
    let invalid_scope = paycheck::models::CreateApiKeyScope {
        org_id: org_a.id.clone(),
        project_id: Some(project_b.id.clone()),
        access: paycheck::models::AccessLevel::Admin,
    };

    let result = queries::create_api_key(
        &mut conn,
        &user.id,
        "test-key",
        None,
        true,
        Some(&[invalid_scope]),
    );

    assert!(
        result.is_err(),
        "creating API key with cross-org project scope should fail"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("does not belong to"),
        "expected 'does not belong to' error, got: {}",
        err
    );
}

#[test]
fn test_api_key_scope_rejects_nonexistent_project() {
    let mut conn = setup_test_db();

    // Create an org
    let org = create_test_org(&mut conn, "Test Org");

    // Create a user who is member of the org (so membership check passes)
    let (user, _, _) =
        create_test_org_member(&mut conn, &org.id, "test@example.com", OrgMemberRole::Member);

    // Try to create an API key with a scope that references a non-existent project
    let invalid_scope = paycheck::models::CreateApiKeyScope {
        org_id: org.id.clone(),
        project_id: Some("nonexistent_project_id".to_string()),
        access: paycheck::models::AccessLevel::View,
    };

    let result = queries::create_api_key(
        &mut conn,
        &user.id,
        "test-key",
        None,
        true,
        Some(&[invalid_scope]),
    );

    assert!(
        result.is_err(),
        "creating API key with nonexistent project scope should fail"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("not found"),
        "expected 'not found' error, got: {}",
        err
    );
}

#[test]
fn test_api_key_scope_accepts_valid_project() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();

    // Create an org and project
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

    // Create a user who is member of the org (so membership check passes)
    let (user, _, _) =
        create_test_org_member(&mut conn, &org.id, "test@example.com", OrgMemberRole::Member);

    // Create an API key with a valid scope (project belongs to org, user is member)
    let valid_scope = paycheck::models::CreateApiKeyScope {
        org_id: org.id.clone(),
        project_id: Some(project.id.clone()),
        access: paycheck::models::AccessLevel::Admin,
    };

    let result = queries::create_api_key(
        &mut conn,
        &user.id,
        "test-key",
        None,
        true,
        Some(&[valid_scope]),
    );

    assert!(
        result.is_ok(),
        "creating API key with valid project scope should succeed, got: {:?}",
        result.err()
    );

    // Verify the scope was created
    let (api_key, _full_key) = result.unwrap();
    let scopes = queries::get_api_key_scopes(&mut conn, &api_key.id).expect("Get scopes failed");
    assert_eq!(scopes.len(), 1, "should have exactly 1 scope");
    assert_eq!(scopes[0].org_id, org.id, "scope org_id should match input");
    assert_eq!(
        scopes[0].project_id,
        Some(project.id),
        "scope project_id should match input"
    );
}
