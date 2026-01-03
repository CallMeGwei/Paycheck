//! Database CRUD operation tests for core entities

mod common;

use common::*;

// ============ Operator Tests ============

#[test]
fn test_create_operator() {
    let conn = setup_test_db();
    let (operator, api_key) = create_test_operator(&conn, "test@example.com", OperatorRole::Admin);

    assert!(!operator.id.is_empty());
    assert_eq!(operator.email, "test@example.com");
    assert_eq!(operator.role, OperatorRole::Admin);
    assert!(!api_key.is_empty());
    assert!(api_key.starts_with("pc_"));
}

#[test]
fn test_get_operator_by_id() {
    let conn = setup_test_db();
    let (created, _) = create_test_operator(&conn, "test@example.com", OperatorRole::Owner);

    let fetched = queries::get_operator_by_id(&conn, &created.id)
        .expect("Query failed")
        .expect("Operator not found");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.email, created.email);
    assert_eq!(fetched.role, created.role);
}

#[test]
fn test_get_operator_by_api_key() {
    let conn = setup_test_db();
    let (created, api_key) = create_test_operator(&conn, "test@example.com", OperatorRole::View);

    let fetched = queries::get_operator_by_api_key(&conn, &api_key)
        .expect("Query failed")
        .expect("Operator not found");

    assert_eq!(fetched.id, created.id);
}

#[test]
fn test_get_operator_with_invalid_api_key_returns_none() {
    let conn = setup_test_db();
    let _ = create_test_operator(&conn, "test@example.com", OperatorRole::Admin);

    let result = queries::get_operator_by_api_key(&conn, "invalid_key").expect("Query failed");

    assert!(result.is_none());
}

#[test]
fn test_list_operators() {
    let conn = setup_test_db();
    create_test_operator(&conn, "test1@example.com", OperatorRole::Owner);
    create_test_operator(&conn, "test2@example.com", OperatorRole::Admin);
    create_test_operator(&conn, "test3@example.com", OperatorRole::View);

    let operators = queries::list_operators(&conn).expect("Query failed");

    assert_eq!(operators.len(), 3);
}

#[test]
fn test_update_operator() {
    let conn = setup_test_db();
    let (operator, _) = create_test_operator(&conn, "test@example.com", OperatorRole::View);

    let update = UpdateOperator {
        name: Some("Updated Name".to_string()),
        role: Some(OperatorRole::Admin),
    };
    queries::update_operator(&conn, &operator.id, &update).expect("Update failed");

    let updated = queries::get_operator_by_id(&conn, &operator.id)
        .expect("Query failed")
        .expect("Operator not found");

    assert_eq!(updated.name, "Updated Name");
    assert_eq!(updated.role, OperatorRole::Admin);
}

#[test]
fn test_delete_operator() {
    let conn = setup_test_db();
    let (operator, _) = create_test_operator(&conn, "test@example.com", OperatorRole::Admin);

    let deleted = queries::delete_operator(&conn, &operator.id).expect("Delete failed");
    assert!(deleted);

    let result = queries::get_operator_by_id(&conn, &operator.id).expect("Query failed");
    assert!(result.is_none());
}

// ============ Organization Tests ============

#[test]
fn test_create_organization() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Organization");

    assert!(!org.id.is_empty());
    assert_eq!(org.name, "Test Organization");
    assert!(org.created_at > 0);
}

#[test]
fn test_get_organization_by_id() {
    let conn = setup_test_db();
    let created = create_test_org(&conn, "Test Org");

    let fetched = queries::get_organization_by_id(&conn, &created.id)
        .expect("Query failed")
        .expect("Organization not found");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.name, created.name);
}

#[test]
fn test_list_organizations() {
    let conn = setup_test_db();
    create_test_org(&conn, "Org 1");
    create_test_org(&conn, "Org 2");

    let orgs = queries::list_organizations(&conn).expect("Query failed");
    assert_eq!(orgs.len(), 2);
}

#[test]
fn test_update_organization() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Original Name");

    let update = UpdateOrganization {
        name: Some("Updated Name".to_string()),
        stripe_config: None,
        ls_config: None,
        default_provider: None,
    };
    queries::update_organization(&conn, &org.id, &update, &master_key).expect("Update failed");

    let updated = queries::get_organization_by_id(&conn, &org.id)
        .expect("Query failed")
        .expect("Organization not found");

    assert_eq!(updated.name, "Updated Name");
}

#[test]
fn test_delete_organization() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "To Delete");

    let deleted = queries::delete_organization(&conn, &org.id).expect("Delete failed");
    assert!(deleted);

    let result = queries::get_organization_by_id(&conn, &org.id).expect("Query failed");
    assert!(result.is_none());
}

// ============ Org Member Tests ============

#[test]
fn test_create_org_member() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");
    let (member, api_key) =
        create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);

    assert!(!member.id.is_empty());
    assert_eq!(member.org_id, org.id);
    assert_eq!(member.email, "member@test.com");
    assert_eq!(member.role, OrgMemberRole::Owner);
    assert!(api_key.starts_with("pc_"));
}

#[test]
fn test_get_org_member_by_api_key() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");
    let (created, api_key) =
        create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Admin);

    let fetched = queries::get_org_member_by_api_key(&conn, &api_key)
        .expect("Query failed")
        .expect("Member not found");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.org_id, org.id);
}

#[test]
fn test_list_org_members() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");
    create_test_org_member(&conn, &org.id, "owner@test.com", OrgMemberRole::Owner);
    create_test_org_member(&conn, &org.id, "admin@test.com", OrgMemberRole::Admin);
    create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Member);

    let members = queries::list_org_members(&conn, &org.id).expect("Query failed");
    assert_eq!(members.len(), 3);
}

#[test]
fn test_unique_email_per_org() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");
    create_test_org_member(&conn, &org.id, "same@test.com", OrgMemberRole::Owner);

    // Creating another member with the same email in the same org should fail
    let api_key = queries::generate_api_key();
    let input = CreateOrgMember {
        email: "same@test.com".to_string(),
        name: "Duplicate".to_string(),
        role: OrgMemberRole::Member,
    };
    let result = queries::create_org_member(&conn, &org.id, &input, &api_key);
    assert!(result.is_err());
}

#[test]
fn test_same_email_different_orgs() {
    let conn = setup_test_db();
    let org1 = create_test_org(&conn, "Org 1");
    let org2 = create_test_org(&conn, "Org 2");

    // Same email should work in different orgs
    let (m1, _) = create_test_org_member(&conn, &org1.id, "same@test.com", OrgMemberRole::Owner);
    let (m2, _) = create_test_org_member(&conn, &org2.id, "same@test.com", OrgMemberRole::Owner);

    assert_eq!(m1.email, m2.email);
    assert_ne!(m1.org_id, m2.org_id);
}

// ============ Project Tests ============

#[test]
fn test_create_project() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);

    assert!(!project.id.is_empty());
    assert_eq!(project.org_id, org.id);
    assert_eq!(project.name, "My App");
    assert_eq!(project.license_key_prefix, "TEST");
    // Verify keypair was generated
    assert!(!project.private_key.is_empty());
    assert!(!project.public_key.is_empty());
}

#[test]
fn test_get_project_by_id() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let created = create_test_project(&conn, &org.id, "My App", &master_key);

    let fetched = queries::get_project_by_id(&conn, &created.id)
        .expect("Query failed")
        .expect("Project not found");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.name, created.name);
    assert_eq!(fetched.public_key, created.public_key);
}

#[test]
fn test_list_projects_for_org() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    create_test_project(&conn, &org.id, "App 1", &master_key);
    create_test_project(&conn, &org.id, "App 2", &master_key);

    let projects = queries::list_projects_for_org(&conn, &org.id).expect("Query failed");
    assert_eq!(projects.len(), 2);
}

#[test]
fn test_update_org_stripe_config() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");

    let stripe_config = StripeConfig {
        secret_key: "sk_test_xxx".to_string(),
        publishable_key: "pk_test_xxx".to_string(),
        webhook_secret: "whsec_xxx".to_string(),
    };

    let update = UpdateOrganization {
        name: None,
        stripe_config: Some(stripe_config.clone()),
        ls_config: None,
        default_provider: None,
    };

    queries::update_organization(&conn, &org.id, &update, &master_key).expect("Update failed");

    let updated = queries::get_organization_by_id(&conn, &org.id)
        .expect("Query failed")
        .expect("Organization not found");

    assert!(updated.has_stripe_config());
    let decrypted = updated
        .decrypt_stripe_config(&master_key)
        .expect("Decryption failed")
        .expect("Config not found");
    assert_eq!(decrypted.secret_key, "sk_test_xxx");

    // Verify the raw data is actually encrypted (has magic bytes)
    assert!(updated.stripe_config_encrypted.is_some());
    let raw = updated.stripe_config_encrypted.as_ref().unwrap();
    assert!(
        raw.starts_with(b"ENC1"),
        "Config should be encrypted with ENC1 magic bytes"
    );
}

#[test]
fn test_update_org_lemonsqueezy_config() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");

    let ls_config = LemonSqueezyConfig {
        api_key: "ls_test_api_key".to_string(),
        store_id: "store_12345".to_string(),
        webhook_secret: "whsec_ls_xxx".to_string(),
    };

    let update = UpdateOrganization {
        name: None,
        stripe_config: None,
        ls_config: Some(ls_config.clone()),
        default_provider: None,
    };

    queries::update_organization(&conn, &org.id, &update, &master_key).expect("Update failed");

    let updated = queries::get_organization_by_id(&conn, &org.id)
        .expect("Query failed")
        .expect("Organization not found");

    assert!(updated.has_ls_config());
    let decrypted = updated
        .decrypt_ls_config(&master_key)
        .expect("Decryption failed")
        .expect("Config not found");
    assert_eq!(decrypted.api_key, "ls_test_api_key");
    assert_eq!(decrypted.store_id, "store_12345");

    // Verify encryption
    let raw = updated.ls_config_encrypted.as_ref().unwrap();
    assert!(raw.starts_with(b"ENC1"), "Config should be encrypted");
}

#[test]
fn test_update_org_both_payment_configs() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");

    let stripe_config = StripeConfig {
        secret_key: "sk_test_both".to_string(),
        publishable_key: "pk_test_both".to_string(),
        webhook_secret: "whsec_both".to_string(),
    };

    let ls_config = LemonSqueezyConfig {
        api_key: "ls_both_key".to_string(),
        store_id: "store_both".to_string(),
        webhook_secret: "whsec_ls_both".to_string(),
    };

    let update = UpdateOrganization {
        name: None,
        stripe_config: Some(stripe_config),
        ls_config: Some(ls_config),
        default_provider: Some(Some("stripe".to_string())),
    };

    queries::update_organization(&conn, &org.id, &update, &master_key).expect("Update failed");

    let updated = queries::get_organization_by_id(&conn, &org.id)
        .expect("Query failed")
        .expect("Organization not found");

    // Both configs should be present and decryptable
    assert!(updated.has_stripe_config());
    assert!(updated.has_ls_config());

    let stripe = updated
        .decrypt_stripe_config(&master_key)
        .expect("Stripe decryption failed")
        .expect("Stripe config not found");
    assert_eq!(stripe.secret_key, "sk_test_both");

    let ls = updated
        .decrypt_ls_config(&master_key)
        .expect("LS decryption failed")
        .expect("LS config not found");
    assert_eq!(ls.api_key, "ls_both_key");

    assert_eq!(updated.default_provider, Some("stripe".to_string()));
}

#[test]
fn test_payment_config_wrong_key_fails() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let wrong_key = MasterKey::from_bytes([1u8; 32]); // Different key
    let org = create_test_org(&conn, "Test Org");

    let stripe_config = StripeConfig {
        secret_key: "sk_secret".to_string(),
        publishable_key: "pk_secret".to_string(),
        webhook_secret: "whsec_secret".to_string(),
    };

    let update = UpdateOrganization {
        name: None,
        stripe_config: Some(stripe_config),
        ls_config: None,
        default_provider: None,
    };

    queries::update_organization(&conn, &org.id, &update, &master_key).expect("Update failed");

    let updated = queries::get_organization_by_id(&conn, &org.id)
        .expect("Query failed")
        .expect("Organization not found");

    // Decryption with wrong key should fail
    let result = updated.decrypt_stripe_config(&wrong_key);
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

// ============ Product Tests ============

#[test]
fn test_create_product() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

    assert!(!product.id.is_empty());
    assert_eq!(product.project_id, project.id);
    assert_eq!(product.name, "Pro Plan");
    assert_eq!(product.tier, "pro");
    assert_eq!(product.license_exp_days, Some(365));
    assert_eq!(product.device_limit, 3);
    assert_eq!(product.activation_limit, 5);
    assert_eq!(product.features, vec!["feature1", "feature2"]);
}

#[test]
fn test_get_product_by_id() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let created = create_test_product(&conn, &project.id, "Enterprise", "enterprise");

    let fetched = queries::get_product_by_id(&conn, &created.id)
        .expect("Query failed")
        .expect("Product not found");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.tier, "enterprise");
}

#[test]
fn test_list_products_for_project() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    create_test_product(&conn, &project.id, "Free", "free");
    create_test_product(&conn, &project.id, "Pro", "pro");
    create_test_product(&conn, &project.id, "Enterprise", "enterprise");

    let products = queries::list_products_for_project(&conn, &project.id).expect("Query failed");
    assert_eq!(products.len(), 3);
}

#[test]
fn test_update_product() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Basic", "basic");

    let update = UpdateProduct {
        name: Some("Premium".to_string()),
        tier: Some("premium".to_string()),
        license_exp_days: Some(Some(730)),
        updates_exp_days: None,
        activation_limit: Some(10),
        device_limit: Some(5),
        features: Some(vec![
            "feature1".to_string(),
            "feature2".to_string(),
            "feature3".to_string(),
        ]),
    };

    queries::update_product(&conn, &product.id, &update).expect("Update failed");

    let updated = queries::get_product_by_id(&conn, &product.id)
        .expect("Query failed")
        .expect("Product not found");

    assert_eq!(updated.name, "Premium");
    assert_eq!(updated.tier, "premium");
    assert_eq!(updated.license_exp_days, Some(730));
    assert_eq!(updated.activation_limit, 10);
    assert_eq!(updated.device_limit, 5);
    assert_eq!(updated.features.len(), 3);
}

#[test]
fn test_delete_product() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "To Delete", "delete");

    let deleted = queries::delete_product(&conn, &product.id).expect("Delete failed");
    assert!(deleted);

    let result = queries::get_product_by_id(&conn, &product.id).expect("Query failed");
    assert!(result.is_none());
}

// ============ Cascade Delete Tests ============

#[test]
fn test_delete_org_cascades_to_members() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");
    let (member, _) =
        create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);

    queries::delete_organization(&conn, &org.id).expect("Delete failed");

    let result = queries::get_org_member_by_id(&conn, &member.id).expect("Query failed");
    assert!(result.is_none());
}

#[test]
fn test_delete_org_cascades_to_projects() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);

    queries::delete_organization(&conn, &org.id).expect("Delete failed");

    let result = queries::get_project_by_id(&conn, &project.id).expect("Query failed");
    assert!(result.is_none());
}

#[test]
fn test_delete_project_cascades_to_products() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    queries::delete_project(&conn, &project.id).expect("Delete failed");

    let result = queries::get_product_by_id(&conn, &product.id).expect("Query failed");
    assert!(result.is_none());
}
