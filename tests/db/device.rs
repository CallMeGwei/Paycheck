//! Database device operation tests

#[path = "../common/mod.rs"]
mod common;

use common::*;

// ============ Device Creation Tests ============

#[test]
fn test_create_device() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    let device = create_test_device(&conn, &license.id, "device-uuid-123", DeviceType::Uuid);

    assert!(!device.id.is_empty(), "device should have a generated ID");
    assert_eq!(device.license_id, license.id, "device should be linked to the correct license");
    assert_eq!(device.device_id, "device-uuid-123", "device_id should match the provided identifier");
    assert_eq!(device.device_type, DeviceType::Uuid, "device_type should be Uuid");
    assert!(!device.jti.is_empty(), "device should have a generated JTI");
    assert_eq!(device.name, Some("Test Device".to_string()), "device name should match the provided value");
}

#[test]
fn test_create_device_machine_type() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    let jti = uuid::Uuid::new_v4().to_string();
    let device = queries::create_device(
        &conn,
        &license.id,
        "machine-hwid-abc",
        DeviceType::Machine,
        &jti,
        Some("Desktop PC"),
    )
    .expect("Failed to create device");

    assert_eq!(device.device_type, DeviceType::Machine, "device_type should be Machine for hardware-derived IDs");
    assert_eq!(device.device_id, "machine-hwid-abc", "device_id should match the provided hardware identifier");
    assert_eq!(device.jti, jti, "JTI should match the provided value");
    assert_eq!(device.name, Some("Desktop PC".to_string()), "device name should match the provided value");
}

#[test]
fn test_create_device_without_name() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    let jti = uuid::Uuid::new_v4().to_string();
    let device = queries::create_device(
        &conn,
        &license.id,
        "device-id",
        DeviceType::Uuid,
        &jti,
        None, // No name
    )
    .expect("Failed to create device");

    assert!(device.name.is_none(), "device name should be None when not provided");
}

// ============ Device Lookup Tests ============

#[test]
fn test_get_device_by_jti() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);
    let created = create_test_device(&conn, &license.id, "device-123", DeviceType::Uuid);

    let fetched = queries::get_device_by_jti(&conn, &created.jti)
        .expect("Query failed")
        .expect("Device not found");

    assert_eq!(fetched.id, created.id, "fetched device ID should match the created device");
    assert_eq!(fetched.jti, created.jti, "fetched device JTI should match");
    assert_eq!(fetched.device_id, created.device_id, "fetched device_id should match");
}

#[test]
fn test_get_device_by_jti_not_found() {
    let conn = setup_test_db();

    let result = queries::get_device_by_jti(&conn, "nonexistent-jti").expect("Query failed");

    assert!(result.is_none(), "lookup by nonexistent JTI should return None");
}

#[test]
fn test_get_device_for_license() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);
    let created = create_test_device(&conn, &license.id, "device-123", DeviceType::Uuid);

    let fetched = queries::get_device_for_license(&conn, &license.id, "device-123")
        .expect("Query failed")
        .expect("Device not found");

    assert_eq!(fetched.id, created.id, "fetched device ID should match the created device");
    assert_eq!(fetched.license_id, license.id, "fetched device should be linked to the correct license");
    assert_eq!(fetched.device_id, "device-123", "fetched device_id should match");
}

#[test]
fn test_get_device_for_license_wrong_device_id() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);
    create_test_device(&conn, &license.id, "device-123", DeviceType::Uuid);

    // Look up with wrong device_id
    let result =
        queries::get_device_for_license(&conn, &license.id, "wrong-device").expect("Query failed");

    assert!(result.is_none(), "lookup with wrong device_id should return None");
}

#[test]
fn test_get_device_for_license_wrong_license() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license1 = create_test_license(&conn, &project.id, &product.id, None);
    let license2 = create_test_license(&conn, &project.id, &product.id, None);
    create_test_device(&conn, &license1.id, "device-123", DeviceType::Uuid);

    // Look up with wrong license_id
    let result =
        queries::get_device_for_license(&conn, &license2.id, "device-123").expect("Query failed");

    assert!(result.is_none(), "lookup with wrong license_id should return None");
}

#[test]
fn test_list_devices_for_license() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    create_test_device(&conn, &license.id, "device-1", DeviceType::Uuid);
    create_test_device(&conn, &license.id, "device-2", DeviceType::Machine);
    create_test_device(&conn, &license.id, "device-3", DeviceType::Uuid);

    let devices = queries::list_devices_for_license(&conn, &license.id).expect("Query failed");

    assert_eq!(devices.len(), 3, "should list all 3 devices for the license");
}

#[test]
fn test_list_devices_for_license_empty() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    let devices = queries::list_devices_for_license(&conn, &license.id).expect("Query failed");

    assert!(devices.is_empty(), "license with no devices should return empty list");
}

// ============ Device Uniqueness Tests ============

#[test]
fn test_device_id_unique_per_license() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    // Create first device
    create_test_device(&conn, &license.id, "device-123", DeviceType::Uuid);

    // Try to create second device with same device_id - should fail
    let jti2 = uuid::Uuid::new_v4().to_string();
    let result = queries::create_device(
        &conn,
        &license.id,
        "device-123", // Same device_id
        DeviceType::Uuid,
        &jti2,
        None,
    );

    assert!(result.is_err(), "duplicate device_id on same license should fail");
}

#[test]
fn test_same_device_id_different_licenses() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license1 = create_test_license(&conn, &project.id, &product.id, None);
    let license2 = create_test_license(&conn, &project.id, &product.id, None);

    // Same device_id on different licenses should work
    let device1 = create_test_device(&conn, &license1.id, "shared-device", DeviceType::Uuid);
    let device2 = create_test_device(&conn, &license2.id, "shared-device", DeviceType::Uuid);

    assert_eq!(device1.device_id, device2.device_id, "both devices should have the same device_id");
    assert_ne!(device1.license_id, device2.license_id, "devices should belong to different licenses");
    assert_ne!(device1.jti, device2.jti, "devices should have unique JTIs");
}

// ============ Device JTI Tests ============

#[test]
fn test_jti_unique_across_devices() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    // Create multiple devices and ensure JTIs are unique
    let mut jtis = std::collections::HashSet::new();
    for i in 0..10 {
        let device = create_test_device(
            &conn,
            &license.id,
            &format!("device-{}", i),
            DeviceType::Uuid,
        );
        assert!(jtis.insert(device.jti), "Duplicate JTI generated");
    }
}

// ============ Device Deletion Tests ============

#[test]
fn test_delete_device() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);
    let device = create_test_device(&conn, &license.id, "device-123", DeviceType::Uuid);

    let deleted = queries::delete_device(&conn, &device.id).expect("Delete failed");
    assert!(deleted, "delete_device should return true when device exists");

    let result = queries::get_device_by_jti(&conn, &device.jti).expect("Query failed");
    assert!(result.is_none(), "deleted device should not be retrievable by JTI");
}

#[test]
fn test_delete_device_not_found() {
    let conn = setup_test_db();

    let deleted = queries::delete_device(&conn, "nonexistent-id").expect("Delete failed");
    assert!(!deleted, "delete_device should return false for nonexistent ID");
}

// ============ Cascade Delete Tests ============

#[test]
fn test_delete_license_cascades_to_devices() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);
    let device = create_test_device(&conn, &license.id, "device-123", DeviceType::Uuid);

    // Delete product which cascades to license
    queries::delete_product(&conn, &product.id).expect("Delete failed");

    let result = queries::get_device_by_jti(&conn, &device.jti).expect("Query failed");
    assert!(result.is_none(), "device should be deleted when parent product is deleted (cascade)");
}

// ============ Device Count Tests ============

#[test]
fn test_count_devices_for_license() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    // Start with no devices
    let devices = queries::list_devices_for_license(&conn, &license.id).expect("Query failed");
    assert_eq!(devices.len(), 0, "new license should have 0 devices");

    // Add devices and verify count
    create_test_device(&conn, &license.id, "device-1", DeviceType::Uuid);
    let devices = queries::list_devices_for_license(&conn, &license.id).expect("Query failed");
    assert_eq!(devices.len(), 1, "should have 1 device after first creation");

    create_test_device(&conn, &license.id, "device-2", DeviceType::Uuid);
    let devices = queries::list_devices_for_license(&conn, &license.id).expect("Query failed");
    assert_eq!(devices.len(), 2, "should have 2 devices after second creation");
}
