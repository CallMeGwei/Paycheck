//! Tests for master key rotation
//!
//! These tests verify that all encrypted data is properly re-encrypted
//! when the master key is rotated.

mod common;

use common::*;
use paycheck::db::LicenseKeyRow;
use rusqlite::Connection;

/// Simulate key rotation for a project's private key
fn rotate_project_key(
    conn: &Connection,
    project_id: &str,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> Result<(), String> {
    // Get project
    let project = queries::get_project_by_id(conn, project_id)
        .map_err(|e| e.to_string())?
        .ok_or("Project not found")?;

    // Decrypt with old key
    let plaintext = old_key
        .decrypt_private_key(&project.id, &project.private_key)
        .map_err(|e| format!("Failed to decrypt: {}", e))?;

    // Re-encrypt with new key
    let new_ciphertext = new_key
        .encrypt_private_key(&project.id, &plaintext)
        .map_err(|e| format!("Failed to encrypt: {}", e))?;

    // Update in database
    queries::update_project_private_key(conn, &project.id, &new_ciphertext)
        .map_err(|e| format!("Failed to update: {}", e))?;

    Ok(())
}

/// Simulate key rotation for an organization's payment configs
fn rotate_org_payment_configs(
    conn: &Connection,
    org_id: &str,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> Result<(), String> {
    // Get org
    let org = queries::get_organization_by_id(conn, org_id)
        .map_err(|e| e.to_string())?
        .ok_or("Org not found")?;

    // Rotate Stripe config if present
    let new_stripe = if let Some(ref encrypted) = org.stripe_config_encrypted {
        let plaintext = old_key
            .decrypt_private_key(&org.id, encrypted)
            .map_err(|e| format!("Failed to decrypt Stripe config: {}", e))?;
        let new_enc = new_key
            .encrypt_private_key(&org.id, &plaintext)
            .map_err(|e| format!("Failed to encrypt Stripe config: {}", e))?;
        Some(new_enc)
    } else {
        None
    };

    // Rotate LemonSqueezy config if present
    let new_ls = if let Some(ref encrypted) = org.ls_config_encrypted {
        let plaintext = old_key
            .decrypt_private_key(&org.id, encrypted)
            .map_err(|e| format!("Failed to decrypt LS config: {}", e))?;
        let new_enc = new_key
            .encrypt_private_key(&org.id, &plaintext)
            .map_err(|e| format!("Failed to encrypt LS config: {}", e))?;
        Some(new_enc)
    } else {
        None
    };

    // Update in database
    queries::update_organization_payment_configs(
        conn,
        &org.id,
        new_stripe.as_deref(),
        new_ls.as_deref(),
    )
    .map_err(|e| format!("Failed to update: {}", e))?;

    Ok(())
}

/// Simulate key rotation for all license keys in a project
fn rotate_license_keys(
    conn: &Connection,
    project_id: &str,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> Result<(), String> {
    // Get all license key rows (encrypted)
    let rows: Vec<LicenseKeyRow> = queries::list_all_license_key_rows(conn)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|r| r.project_id == project_id)
        .collect();

    for row in rows {
        // Decrypt with old key
        let plaintext = old_key
            .decrypt_private_key(&row.project_id, &row.encrypted_key)
            .map_err(|e| format!("Failed to decrypt license key {}: {}", row.id, e))?;

        // Re-encrypt with new key
        let new_encrypted = new_key
            .encrypt_private_key(&row.project_id, &plaintext)
            .map_err(|e| format!("Failed to re-encrypt license key {}: {}", row.id, e))?;

        // Update in database
        queries::update_license_key_encrypted(conn, &row.id, &new_encrypted)
            .map_err(|e| format!("Failed to update license key {}: {}", row.id, e))?;
    }

    Ok(())
}

// ============ Project Private Key Rotation ============

#[test]
fn test_project_private_key_rotation_works() {
    let conn = setup_test_db();
    let old_key = MasterKey::from_bytes([1u8; 32]);
    let new_key = MasterKey::from_bytes([2u8; 32]);

    // Create org and project with old key
    let org = create_test_org(&conn, "Test Org");

    // Create project - encryption happens internally with correct project ID
    let (private_key_bytes, public_key) = jwt::generate_keypair();
    let input = CreateProject {
        name: "Test Project".to_string(),
        domain: "test.example.com".to_string(),
        license_key_prefix: "TEST".to_string(),
        allowed_redirect_urls: vec![],
    };
    let project = queries::create_project(
        &conn,
        &org.id,
        &input,
        &private_key_bytes,
        &public_key,
        &old_key,
    )
    .expect("Failed to create project");

    // Verify we can decrypt with old key
    let fetched = queries::get_project_by_id(&conn, &project.id)
        .unwrap()
        .unwrap();
    let decrypted = old_key
        .decrypt_private_key(&project.id, &fetched.private_key)
        .expect("Should decrypt with old key");
    assert_eq!(decrypted, private_key_bytes);

    // Rotate the key
    rotate_project_key(&conn, &project.id, &old_key, &new_key).expect("Rotation should succeed");

    // Verify old key no longer works
    let fetched = queries::get_project_by_id(&conn, &project.id)
        .unwrap()
        .unwrap();
    let result = old_key.decrypt_private_key(&project.id, &fetched.private_key);
    assert!(result.is_err(), "Old key should no longer decrypt");

    // Verify new key works
    let decrypted = new_key
        .decrypt_private_key(&project.id, &fetched.private_key)
        .expect("New key should decrypt");
    assert_eq!(decrypted, private_key_bytes);
}

// ============ Organization Payment Config Rotation ============

#[test]
fn test_org_stripe_config_rotation_works() {
    let conn = setup_test_db();
    let old_key = MasterKey::from_bytes([1u8; 32]);
    let new_key = MasterKey::from_bytes([2u8; 32]);

    // Create org
    let org = create_test_org(&conn, "Test Org");

    // Set up Stripe config with old key
    let stripe_config = r#"{"api_key":"sk_test_123","webhook_secret":"whsec_123"}"#;
    let encrypted_stripe = old_key
        .encrypt_private_key(&org.id, stripe_config.as_bytes())
        .unwrap();

    queries::update_organization_payment_configs(&conn, &org.id, Some(&encrypted_stripe), None)
        .unwrap();

    // Verify we can decrypt with old key
    let fetched = queries::get_organization_by_id(&conn, &org.id)
        .unwrap()
        .unwrap();
    let decrypted = old_key
        .decrypt_private_key(&org.id, fetched.stripe_config_encrypted.as_ref().unwrap())
        .expect("Should decrypt with old key");
    assert_eq!(decrypted, stripe_config.as_bytes());

    // Rotate the key
    rotate_org_payment_configs(&conn, &org.id, &old_key, &new_key)
        .expect("Rotation should succeed");

    // Verify old key no longer works
    let fetched = queries::get_organization_by_id(&conn, &org.id)
        .unwrap()
        .unwrap();
    let result =
        old_key.decrypt_private_key(&org.id, fetched.stripe_config_encrypted.as_ref().unwrap());
    assert!(result.is_err(), "Old key should no longer decrypt");

    // Verify new key works
    let decrypted = new_key
        .decrypt_private_key(&org.id, fetched.stripe_config_encrypted.as_ref().unwrap())
        .expect("New key should decrypt");
    assert_eq!(decrypted, stripe_config.as_bytes());
}

#[test]
fn test_org_lemonsqueezy_config_rotation_works() {
    let conn = setup_test_db();
    let old_key = MasterKey::from_bytes([1u8; 32]);
    let new_key = MasterKey::from_bytes([2u8; 32]);

    // Create org
    let org = create_test_org(&conn, "Test Org");

    // Set up LemonSqueezy config with old key
    let ls_config = r#"{"api_key":"ls_test_123","webhook_secret":"lswhsec_123"}"#;
    let encrypted_ls = old_key
        .encrypt_private_key(&org.id, ls_config.as_bytes())
        .unwrap();

    queries::update_organization_payment_configs(&conn, &org.id, None, Some(&encrypted_ls))
        .unwrap();

    // Verify we can decrypt with old key
    let fetched = queries::get_organization_by_id(&conn, &org.id)
        .unwrap()
        .unwrap();
    let decrypted = old_key
        .decrypt_private_key(&org.id, fetched.ls_config_encrypted.as_ref().unwrap())
        .expect("Should decrypt with old key");
    assert_eq!(decrypted, ls_config.as_bytes());

    // Rotate the key
    rotate_org_payment_configs(&conn, &org.id, &old_key, &new_key)
        .expect("Rotation should succeed");

    // Verify old key no longer works
    let fetched = queries::get_organization_by_id(&conn, &org.id)
        .unwrap()
        .unwrap();
    let result =
        old_key.decrypt_private_key(&org.id, fetched.ls_config_encrypted.as_ref().unwrap());
    assert!(result.is_err(), "Old key should no longer decrypt");

    // Verify new key works
    let decrypted = new_key
        .decrypt_private_key(&org.id, fetched.ls_config_encrypted.as_ref().unwrap())
        .expect("New key should decrypt");
    assert_eq!(decrypted, ls_config.as_bytes());
}

// ============ License Key Rotation ============

#[test]
fn test_license_key_unreadable_without_rotation() {
    // This test demonstrates what happens if license keys are NOT rotated
    // during master key rotation - they become unreadable. This documents
    // the importance of the license key rotation step.

    let conn = setup_test_db();
    let old_key = MasterKey::from_bytes([1u8; 32]);
    let new_key = MasterKey::from_bytes([2u8; 32]);

    // Create org, project, product with old key
    let org = create_test_org(&conn, "Test Org");

    // Create project - encryption happens internally with correct project ID
    let (private_key_bytes, public_key) = jwt::generate_keypair();
    let input = CreateProject {
        name: "Test Project".to_string(),
        domain: "test.example.com".to_string(),
        license_key_prefix: "TEST".to_string(),
        allowed_redirect_urls: vec![],
    };
    let project = queries::create_project(
        &conn,
        &org.id,
        &input,
        &private_key_bytes,
        &public_key,
        &old_key,
    )
    .expect("Failed to create project");

    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

    // Create license key with old master key
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        &project.license_key_prefix,
        Some(future_timestamp(365)),
        &old_key,
    );

    // Store the original plaintext key for comparison
    let original_key = license.key.clone();

    // Verify we can read the license key with old master key
    let fetched = queries::get_license_key_by_id(&conn, &license.id, &old_key)
        .expect("Query should succeed")
        .expect("License should exist");
    assert_eq!(fetched.key, original_key);

    // Simulate what happens after key rotation:
    // Project keys get rotated, but license keys do NOT
    rotate_project_key(&conn, &project.id, &old_key, &new_key)
        .expect("Project rotation should succeed");

    // License keys are still encrypted with old key (we didn't rotate them)
    // Attempting to read with new key should FAIL
    let result = queries::get_license_key_by_id(&conn, &license.id, &new_key);

    // Without license key rotation, decryption fails
    assert!(
        result.is_err() || result.unwrap().is_none() || {
            // If we get here, check if the key is corrupted/wrong
            let maybe_license = queries::get_license_key_by_id(&conn, &license.id, &new_key);
            match maybe_license {
                Ok(Some(l)) => l.key != original_key, // Key is corrupted
                _ => true,                            // Error or not found
            }
        },
        "License key should not be readable with new key when not rotated"
    );

    // Double-check: the license key IS still readable with the OLD key
    // (which would be unavailable in production after rotation)
    let still_works_with_old = queries::get_license_key_by_id(&conn, &license.id, &old_key)
        .expect("Query should succeed")
        .expect("License should exist");
    assert_eq!(still_works_with_old.key, original_key);
}

#[test]
fn test_license_key_should_be_readable_after_rotation() {
    // This test verifies that license keys are properly rotated
    // and can be decrypted with the new master key.

    let conn = setup_test_db();
    let old_key = MasterKey::from_bytes([1u8; 32]);
    let new_key = MasterKey::from_bytes([2u8; 32]);

    // Setup
    let org = create_test_org(&conn, "Test Org");
    let (private_key_bytes, public_key) = jwt::generate_keypair();
    let input = CreateProject {
        name: "Test Project".to_string(),
        domain: "test.example.com".to_string(),
        license_key_prefix: "TEST".to_string(),
        allowed_redirect_urls: vec![],
    };
    let project = queries::create_project(
        &conn,
        &org.id,
        &input,
        &private_key_bytes,
        &public_key,
        &old_key,
    )
    .unwrap();

    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        &project.license_key_prefix,
        Some(future_timestamp(365)),
        &old_key,
    );
    let original_key = license.key.clone();

    // Rotate project key
    rotate_project_key(&conn, &project.id, &old_key, &new_key).unwrap();

    // Rotate license keys
    rotate_license_keys(&conn, &project.id, &old_key, &new_key).unwrap();

    // After rotation, license key should be readable with new key
    let result = queries::get_license_key_by_id(&conn, &license.id, &new_key);

    match result {
        Ok(Some(fetched)) => {
            assert_eq!(
                fetched.key, original_key,
                "License key should be readable after rotation"
            );
        }
        Ok(None) => {
            panic!("License key not found after rotation");
        }
        Err(e) => {
            panic!("License key decryption failed after rotation: {}", e);
        }
    }

    // Verify old key no longer works
    let old_result = queries::get_license_key_by_id(&conn, &license.id, &old_key);
    assert!(
        old_result.is_err(),
        "Old key should no longer decrypt license key after rotation"
    );
}
