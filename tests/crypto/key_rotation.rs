//! Tests for master key rotation
//!
//! These tests verify that all encrypted data is properly re-encrypted
//! when the master key is rotated.
//!
//! Note: Licenses are no longer encrypted, so only project private keys
//! and organization payment configs need rotation.

#[path = "../common/mod.rs"]
mod common;

use common::*;
use rusqlite::Connection;

// ============ Test Key Constants ============

/// Bytes for the "old" master key used before rotation
const OLD_KEY_BYTES: [u8; 32] = [1u8; 32];
/// Bytes for the "new" master key used after rotation
const NEW_KEY_BYTES: [u8; 32] = [2u8; 32];

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
    queries::update_organization_encrypted_configs(
        conn,
        &org.id,
        new_stripe.as_deref(),
        new_ls.as_deref(),
        None, // resend_api_key - not rotated in this helper
    )
    .map_err(|e| format!("Failed to update: {}", e))?;

    Ok(())
}

// ============ Project Private Key Rotation ============

#[test]
fn test_project_private_key_reencrypts_with_new_master_key() {
    let conn = setup_test_db();
    let old_key = MasterKey::from_bytes(OLD_KEY_BYTES);
    let new_key = MasterKey::from_bytes(NEW_KEY_BYTES);

    // Create org and project with old key
    let org = create_test_org(&conn, "Test Org");

    // Create project - encryption happens internally with correct project ID
    let (private_key_bytes, public_key) = jwt::generate_keypair();
    let input = CreateProject {
        name: "Test Project".to_string(),
        license_key_prefix: "TEST".to_string(),
        redirect_url: None,
        email_from: None,
        email_enabled: true,
        email_webhook_url: None,
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
    assert_eq!(
        decrypted, private_key_bytes,
        "decrypted private key should match original plaintext before rotation"
    );

    // Rotate the key
    rotate_project_key(&conn, &project.id, &old_key, &new_key).expect("Rotation should succeed");

    // Verify old key no longer works
    let fetched = queries::get_project_by_id(&conn, &project.id)
        .unwrap()
        .unwrap();
    let result = old_key.decrypt_private_key(&project.id, &fetched.private_key);
    assert!(
        result.is_err(),
        "old key should fail to decrypt after rotation"
    );

    // Verify new key works
    let decrypted = new_key
        .decrypt_private_key(&project.id, &fetched.private_key)
        .expect("New key should decrypt");
    assert_eq!(
        decrypted, private_key_bytes,
        "decrypted private key should match original plaintext after rotation with new key"
    );
}

// ============ Organization Payment Config Rotation ============

#[test]
fn test_org_stripe_config_reencrypts_with_new_master_key() {
    let conn = setup_test_db();
    let old_key = MasterKey::from_bytes(OLD_KEY_BYTES);
    let new_key = MasterKey::from_bytes(NEW_KEY_BYTES);

    // Create org
    let org = create_test_org(&conn, "Test Org");

    // Set up Stripe config with old key
    let stripe_config = r#"{"api_key":"sk_test_123","webhook_secret":"whsec_123"}"#;
    let encrypted_stripe = old_key
        .encrypt_private_key(&org.id, stripe_config.as_bytes())
        .unwrap();

    queries::update_organization_encrypted_configs(
        &conn,
        &org.id,
        Some(&encrypted_stripe),
        None,
        None,
    )
    .unwrap();

    // Verify we can decrypt with old key
    let fetched = queries::get_organization_by_id(&conn, &org.id)
        .unwrap()
        .unwrap();
    let decrypted = old_key
        .decrypt_private_key(&org.id, fetched.stripe_config_encrypted.as_ref().unwrap())
        .expect("Should decrypt with old key");
    assert_eq!(
        decrypted,
        stripe_config.as_bytes(),
        "decrypted Stripe config should match original JSON before rotation"
    );

    // Rotate the key
    rotate_org_payment_configs(&conn, &org.id, &old_key, &new_key)
        .expect("Rotation should succeed");

    // Verify old key no longer works
    let fetched = queries::get_organization_by_id(&conn, &org.id)
        .unwrap()
        .unwrap();
    let result =
        old_key.decrypt_private_key(&org.id, fetched.stripe_config_encrypted.as_ref().unwrap());
    assert!(
        result.is_err(),
        "old key should fail to decrypt Stripe config after rotation"
    );

    // Verify new key works
    let decrypted = new_key
        .decrypt_private_key(&org.id, fetched.stripe_config_encrypted.as_ref().unwrap())
        .expect("New key should decrypt");
    assert_eq!(
        decrypted,
        stripe_config.as_bytes(),
        "decrypted Stripe config should match original JSON after rotation with new key"
    );
}

#[test]
fn test_org_lemonsqueezy_config_reencrypts_with_new_master_key() {
    let conn = setup_test_db();
    let old_key = MasterKey::from_bytes(OLD_KEY_BYTES);
    let new_key = MasterKey::from_bytes(NEW_KEY_BYTES);

    // Create org
    let org = create_test_org(&conn, "Test Org");

    // Set up LemonSqueezy config with old key
    let ls_config = r#"{"api_key":"ls_test_123","webhook_secret":"lswhsec_123"}"#;
    let encrypted_ls = old_key
        .encrypt_private_key(&org.id, ls_config.as_bytes())
        .unwrap();

    queries::update_organization_encrypted_configs(&conn, &org.id, None, Some(&encrypted_ls), None)
        .unwrap();

    // Verify we can decrypt with old key
    let fetched = queries::get_organization_by_id(&conn, &org.id)
        .unwrap()
        .unwrap();
    let decrypted = old_key
        .decrypt_private_key(&org.id, fetched.ls_config_encrypted.as_ref().unwrap())
        .expect("Should decrypt with old key");
    assert_eq!(
        decrypted,
        ls_config.as_bytes(),
        "decrypted LemonSqueezy config should match original JSON before rotation"
    );

    // Rotate the key
    rotate_org_payment_configs(&conn, &org.id, &old_key, &new_key)
        .expect("Rotation should succeed");

    // Verify old key no longer works
    let fetched = queries::get_organization_by_id(&conn, &org.id)
        .unwrap()
        .unwrap();
    let result =
        old_key.decrypt_private_key(&org.id, fetched.ls_config_encrypted.as_ref().unwrap());
    assert!(
        result.is_err(),
        "old key should fail to decrypt LemonSqueezy config after rotation"
    );

    // Verify new key works
    let decrypted = new_key
        .decrypt_private_key(&org.id, fetched.ls_config_encrypted.as_ref().unwrap())
        .expect("New key should decrypt");
    assert_eq!(
        decrypted,
        ls_config.as_bytes(),
        "decrypted LemonSqueezy config should match original JSON after rotation with new key"
    );
}
