//! Tests for soft delete, restore, and purge functionality

#[path = "../common/mod.rs"]
mod common;

use common::{
    create_test_license, create_test_operator, create_test_org, create_test_org_member,
    create_test_product, create_test_project, future_timestamp, now, queries, setup_test_db,
    test_master_key, OperatorRole, OrgMemberRole, LICENSE_VALID_DAYS, ONE_MONTH,
};

// ============ Soft Delete Mechanics ============

#[test]
fn test_soft_delete_user_sets_deleted_at_and_depth() {
    let conn = setup_test_db();
    let (user, _operator, _api_key) =
        create_test_operator(&conn, "test@example.com", OperatorRole::Admin);

    // Soft delete the user
    queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

    // User should not be found via normal query
    let result = queries::get_user_by_id(&conn, &user.id).expect("Query failed");
    assert!(
        result.is_none(),
        "User should not be found after soft delete"
    );

    // User should be found via deleted query
    let deleted = queries::get_deleted_user_by_id(&conn, &user.id)
        .expect("Query failed")
        .expect("Deleted user should be found");

    assert!(deleted.deleted_at.is_some(), "deleted_at should be set");
    assert_eq!(
        deleted.deleted_cascade_depth,
        Some(0),
        "depth should be 0 for direct delete"
    );
}

#[test]
fn test_soft_delete_user_cascades_to_operator() {
    let conn = setup_test_db();
    let (user, operator, _api_key) =
        create_test_operator(&conn, "test@example.com", OperatorRole::Admin);

    // Soft delete the user
    queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

    // Operator should not be found via normal query
    let result = queries::get_operator_by_id(&conn, &operator.id).expect("Query failed");
    assert!(
        result.is_none(),
        "Operator should not be found after user soft delete"
    );

    // Operator should be found via deleted query with depth > 0
    let deleted = queries::get_deleted_operator_by_id(&conn, &operator.id)
        .expect("Query failed")
        .expect("Deleted operator should be found");

    assert!(deleted.deleted_at.is_some(), "deleted_at should be set");
    assert_eq!(
        deleted.deleted_cascade_depth,
        Some(1),
        "depth should be 1 for cascade delete"
    );
}

#[test]
fn test_soft_delete_user_cascades_to_org_members() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");
    let (user, member, _api_key) =
        create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);

    // Soft delete the user
    queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

    // Org member should not be found via normal query
    let result = queries::get_org_member_by_id(&conn, &member.id).expect("Query failed");
    assert!(
        result.is_none(),
        "Org member should not be found after user soft delete"
    );

    // Org member should be found via deleted query with depth > 0
    let deleted = queries::get_deleted_org_member_by_id(&conn, &member.id)
        .expect("Query failed")
        .expect("Deleted org member should be found");

    assert!(deleted.deleted_at.is_some(), "deleted_at should be set");
    assert_eq!(
        deleted.deleted_cascade_depth,
        Some(1),
        "depth should be 1 for cascade delete"
    );
}

#[test]
fn test_soft_delete_organization_cascades_to_children() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let (_user, member, _api_key) =
        create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Soft delete the organization
    queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

    // Org should not be found via normal query
    assert!(
        queries::get_organization_by_id(&conn, &org.id)
            .expect("Query failed")
            .is_none(),
        "Organization should not be found via normal query after soft delete"
    );

    // Org member should be cascade deleted (depth 1)
    let deleted_member = queries::get_deleted_org_member_by_id(&conn, &member.id)
        .expect("Query failed")
        .expect("Deleted member should be found");
    assert_eq!(
        deleted_member.deleted_cascade_depth,
        Some(1),
        "Org member should be cascade-deleted at depth 1"
    );

    // Project should be cascade deleted (depth 1)
    let deleted_project = queries::get_deleted_project_by_id(&conn, &project.id)
        .expect("Query failed")
        .expect("Deleted project should be found");
    assert_eq!(
        deleted_project.deleted_cascade_depth,
        Some(1),
        "Project should be cascade-deleted at depth 1"
    );

    // Product should be cascade deleted (depth 2)
    let deleted_product = queries::get_deleted_product_by_id(&conn, &product.id)
        .expect("Query failed")
        .expect("Deleted product should be found");
    assert_eq!(
        deleted_product.deleted_cascade_depth,
        Some(2),
        "Product should be cascade-deleted at depth 2"
    );

    // License should be cascade deleted (depth 3)
    let deleted_license = queries::get_deleted_license_by_id(&conn, &license.id)
        .expect("Query failed")
        .expect("Deleted license should be found");
    assert_eq!(
        deleted_license.deleted_cascade_depth,
        Some(3),
        "License should be cascade-deleted at depth 3"
    );
}

#[test]
fn test_soft_delete_project_cascades_to_products_and_licenses() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Soft delete the project
    queries::soft_delete_project(&conn, &project.id).expect("Soft delete failed");

    // Project deleted at depth 0
    let deleted_project = queries::get_deleted_project_by_id(&conn, &project.id)
        .expect("Query failed")
        .expect("Deleted project should be found");
    assert_eq!(
        deleted_project.deleted_cascade_depth,
        Some(0),
        "Directly deleted project should have depth 0"
    );

    // Product cascade deleted at depth 1
    let deleted_product = queries::get_deleted_product_by_id(&conn, &product.id)
        .expect("Query failed")
        .expect("Deleted product should be found");
    assert_eq!(
        deleted_product.deleted_cascade_depth,
        Some(1),
        "Product should be cascade-deleted at depth 1"
    );

    // License cascade deleted at depth 2
    let deleted_license = queries::get_deleted_license_by_id(&conn, &license.id)
        .expect("Query failed")
        .expect("Deleted license should be found");
    assert_eq!(
        deleted_license.deleted_cascade_depth,
        Some(2),
        "License should be cascade-deleted at depth 2"
    );
}

#[test]
fn test_soft_delete_product_cascades_to_licenses() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Soft delete the product
    queries::soft_delete_product(&conn, &product.id).expect("Soft delete failed");

    // Product deleted at depth 0
    let deleted_product = queries::get_deleted_product_by_id(&conn, &product.id)
        .expect("Query failed")
        .expect("Deleted product should be found");
    assert_eq!(
        deleted_product.deleted_cascade_depth,
        Some(0),
        "Directly deleted product should have depth 0"
    );

    // License cascade deleted at depth 1
    let deleted_license = queries::get_deleted_license_by_id(&conn, &license.id)
        .expect("Query failed")
        .expect("Deleted license should be found");
    assert_eq!(
        deleted_license.deleted_cascade_depth,
        Some(1),
        "License should be cascade-deleted at depth 1"
    );
}

// ============ Query Filtering Tests ============

#[test]
fn test_list_users_excludes_deleted_by_default() {
    let conn = setup_test_db();
    create_test_operator(&conn, "active1@example.com", OperatorRole::Admin);
    let (user_to_delete, _op, _key) =
        create_test_operator(&conn, "deleted@example.com", OperatorRole::Admin);
    create_test_operator(&conn, "active2@example.com", OperatorRole::Admin);

    // Soft delete one user
    queries::soft_delete_user(&conn, &user_to_delete.id).expect("Soft delete failed");

    // List should exclude deleted user
    let (users, total) = queries::list_users_paginated(&conn, 100, 0, false).expect("Query failed");
    assert_eq!(total, 2, "Total should be 2 (excluding deleted)");
    assert_eq!(users.len(), 2, "Should return 2 users");
    assert!(
        users.iter().all(|u| u.email != "deleted@example.com"),
        "Deleted user should not appear in list"
    );
}

#[test]
fn test_list_users_includes_deleted_when_requested() {
    let conn = setup_test_db();
    create_test_operator(&conn, "active1@example.com", OperatorRole::Admin);
    let (user_to_delete, _op, _key) =
        create_test_operator(&conn, "deleted@example.com", OperatorRole::Admin);
    create_test_operator(&conn, "active2@example.com", OperatorRole::Admin);

    // Soft delete one user
    queries::soft_delete_user(&conn, &user_to_delete.id).expect("Soft delete failed");

    // List with include_deleted=true should include all users
    let (users, total) = queries::list_users_paginated(&conn, 100, 0, true).expect("Query failed");
    assert_eq!(total, 3, "Total should be 3 (including deleted)");
    assert_eq!(users.len(), 3, "Should return all 3 users");
    assert!(
        users.iter().any(|u| u.email == "deleted@example.com"),
        "Deleted user should appear when include_deleted=true"
    );
}

#[test]
fn test_list_organizations_excludes_deleted_by_default() {
    let conn = setup_test_db();
    create_test_org(&conn, "Active Org 1");
    let org_to_delete = create_test_org(&conn, "Deleted Org");
    create_test_org(&conn, "Active Org 2");

    // Soft delete one org
    queries::soft_delete_organization(&conn, &org_to_delete.id).expect("Soft delete failed");

    // List should exclude deleted org
    let (orgs, total) =
        queries::list_organizations_paginated(&conn, 100, 0, false).expect("Query failed");
    assert_eq!(total, 2, "Total should be 2 (excluding deleted)");
    assert_eq!(orgs.len(), 2, "Should return 2 organizations");
    assert!(
        orgs.iter().all(|o| o.name != "Deleted Org"),
        "Deleted org should not appear in list"
    );
}

#[test]
fn test_list_organizations_includes_deleted_when_requested() {
    let conn = setup_test_db();
    create_test_org(&conn, "Active Org 1");
    let org_to_delete = create_test_org(&conn, "Deleted Org");
    create_test_org(&conn, "Active Org 2");

    // Soft delete one org
    queries::soft_delete_organization(&conn, &org_to_delete.id).expect("Soft delete failed");

    // List with include_deleted=true should include all orgs
    let (orgs, total) =
        queries::list_organizations_paginated(&conn, 100, 0, true).expect("Query failed");
    assert_eq!(total, 3, "Total should be 3 (including deleted)");
    assert_eq!(orgs.len(), 3, "Should return all 3 organizations");
    assert!(
        orgs.iter().any(|o| o.name == "Deleted Org"),
        "Deleted org should appear when include_deleted=true"
    );
}

// ============ Restore Tests ============

#[test]
fn test_restore_directly_deleted_user_succeeds_without_force() {
    let conn = setup_test_db();
    let (user, _operator, _api_key) =
        create_test_operator(&conn, "test@example.com", OperatorRole::Admin);

    // Soft delete the user
    queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

    // Restore without force should succeed (depth 0)
    let result = queries::restore_user(&conn, &user.id, false);
    assert!(
        result.is_ok(),
        "Restore should succeed for directly deleted user"
    );

    // User should be found again
    let restored = queries::get_user_by_id(&conn, &user.id)
        .expect("Query failed")
        .expect("Restored user should be found");
    assert!(
        restored.deleted_at.is_none(),
        "deleted_at should be cleared"
    );
}

#[test]
fn test_restore_cascade_deleted_operator_requires_force() {
    let conn = setup_test_db();
    let (user, operator, _api_key) =
        create_test_operator(&conn, "test@example.com", OperatorRole::Admin);

    // Soft delete the user (cascades to operator with depth 1)
    queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

    // Restore operator without force should fail (depth > 0)
    let result = queries::restore_operator(&conn, &operator.id, false);
    assert!(
        result.is_err(),
        "Restore should fail for cascade-deleted operator without force"
    );
    let err = result.unwrap_err();
    assert!(err.to_string().contains("cascade") || err.to_string().contains("force"));
}

#[test]
fn test_restore_cascade_deleted_operator_succeeds_with_force() {
    let conn = setup_test_db();
    let (user, operator, _api_key) =
        create_test_operator(&conn, "test@example.com", OperatorRole::Admin);

    // Soft delete the user (cascades to operator with depth 1)
    queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

    // Restore operator with force should succeed
    let result = queries::restore_operator(&conn, &operator.id, true);
    assert!(result.is_ok(), "Restore should succeed with force=true");

    // Operator should be found again
    let restored = queries::get_operator_by_id(&conn, &operator.id)
        .expect("Query failed")
        .expect("Restored operator should be found");
    assert!(
        restored.deleted_at.is_none(),
        "deleted_at should be cleared"
    );
}

#[test]
fn test_restore_user_also_restores_cascade_deleted_children() {
    let conn = setup_test_db();
    let (user, operator, _api_key) =
        create_test_operator(&conn, "test@example.com", OperatorRole::Admin);

    // Soft delete the user (cascades to operator)
    queries::soft_delete_user(&conn, &user.id).expect("Soft delete failed");

    // Restore the user
    queries::restore_user(&conn, &user.id, false).expect("Restore failed");

    // Operator should also be restored (via cascade restore)
    let restored_operator = queries::get_operator_by_id(&conn, &operator.id)
        .expect("Query failed")
        .expect("Restored operator should be found");
    assert!(
        restored_operator.deleted_at.is_none(),
        "Cascade-deleted operator should be restored when parent user is restored"
    );
}

#[test]
fn test_restore_organization_restores_entire_hierarchy() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let (_user, member, _api_key) =
        create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Soft delete the organization (cascades to all children)
    queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

    // Restore the organization
    queries::restore_organization(&conn, &org.id).expect("Restore failed");

    // All entities should be restored
    assert!(
        queries::get_organization_by_id(&conn, &org.id)
            .expect("Query failed")
            .is_some(),
        "Organization should be restored"
    );
    assert!(
        queries::get_org_member_by_id(&conn, &member.id)
            .expect("Query failed")
            .is_some(),
        "Org member should be restored with organization"
    );
    assert!(
        queries::get_project_by_id(&conn, &project.id)
            .expect("Query failed")
            .is_some(),
        "Project should be restored with organization"
    );
    assert!(
        queries::get_product_by_id(&conn, &product.id)
            .expect("Query failed")
            .is_some(),
        "Product should be restored with organization"
    );
    assert!(
        queries::get_license_by_id(&conn, &license.id)
            .expect("Query failed")
            .is_some(),
        "License should be restored with organization"
    );
}

#[test]
fn test_restore_project_restores_products_and_licenses() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Soft delete the project
    queries::soft_delete_project(&conn, &project.id).expect("Soft delete failed");

    // Restore the project
    queries::restore_project(&conn, &project.id, false).expect("Restore failed");

    // All entities should be restored
    assert!(
        queries::get_project_by_id(&conn, &project.id)
            .expect("Query failed")
            .is_some(),
        "Project should be restored"
    );
    assert!(
        queries::get_product_by_id(&conn, &product.id)
            .expect("Query failed")
            .is_some(),
        "Product should be restored with project"
    );
    assert!(
        queries::get_license_by_id(&conn, &license.id)
            .expect("Query failed")
            .is_some(),
        "License should be restored with project"
    );
}

// ============ Selective Cascade Restore Tests ============

#[test]
fn test_restore_only_restores_items_with_matching_timestamp() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product1 = create_test_product(&conn, &project.id, "Product 1", "tier1");
    let product2 = create_test_product(&conn, &project.id, "Product 2", "tier2");

    // Soft delete product1 directly
    queries::soft_delete_product(&conn, &product1.id).expect("Soft delete failed");

    // Wait a tiny bit to ensure different timestamp
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Soft delete project (cascades to product2, not product1 which is already deleted)
    queries::soft_delete_project(&conn, &project.id).expect("Soft delete failed");

    // Restore project - should only restore product2 (cascade-deleted with project)
    // product1 was deleted separately and should stay deleted
    queries::restore_project(&conn, &project.id, false).expect("Restore failed");

    // Project should be restored
    assert!(
        queries::get_project_by_id(&conn, &project.id)
            .expect("Query failed")
            .is_some(),
        "Project should be restored"
    );

    // Product2 should be restored (was cascade-deleted with project)
    assert!(
        queries::get_product_by_id(&conn, &product2.id)
            .expect("Query failed")
            .is_some(),
        "Product2 should be restored (was cascade-deleted with project)"
    );

    // Product1 should still be deleted (was deleted separately before project)
    assert!(
        queries::get_product_by_id(&conn, &product1.id)
            .expect("Query failed")
            .is_none(),
        "Product1 should remain deleted (was deleted separately before project)"
    );
}

// ============ Purge Tests ============

#[test]
fn test_purge_removes_old_soft_deleted_records() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Old Deleted Org");

    // Soft delete the org
    queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

    // Manually set deleted_at to 100 days ago to simulate old deletion
    let old_timestamp = now() - (100 * 86400);
    conn.execute(
        "UPDATE organizations SET deleted_at = ?1 WHERE id = ?2",
        rusqlite::params![old_timestamp, org.id],
    )
    .expect("Update timestamp failed");

    // Purge with 30 day retention
    let result = queries::purge_soft_deleted_records(&conn, ONE_MONTH).expect("Purge failed");

    // Should have purged the organization
    assert!(result.organizations > 0, "Should have purged organization");

    // Org should be completely gone (not even as deleted)
    let gone = queries::get_deleted_organization_by_id(&conn, &org.id).expect("Query failed");
    assert!(
        gone.is_none(),
        "Org should be completely removed after purge"
    );
}

#[test]
fn test_purge_respects_retention_period() {
    let conn = setup_test_db();
    let old_org = create_test_org(&conn, "Old Org");
    let recent_org = create_test_org(&conn, "Recent Org");

    // Soft delete both
    queries::soft_delete_organization(&conn, &old_org.id).expect("Soft delete failed");
    queries::soft_delete_organization(&conn, &recent_org.id).expect("Soft delete failed");

    // Set old_org to 100 days ago
    let old_timestamp = now() - (100 * 86400);
    conn.execute(
        "UPDATE organizations SET deleted_at = ?1 WHERE id = ?2",
        rusqlite::params![old_timestamp, old_org.id],
    )
    .expect("Update timestamp failed");

    // Purge with 30 day retention
    queries::purge_soft_deleted_records(&conn, ONE_MONTH).expect("Purge failed");

    // Old org should be gone
    assert!(
        queries::get_deleted_organization_by_id(&conn, &old_org.id)
            .expect("Query failed")
            .is_none(),
        "Org deleted 100 days ago should be purged with 30-day retention"
    );

    // Recent org should still exist (as deleted)
    assert!(
        queries::get_deleted_organization_by_id(&conn, &recent_org.id)
            .expect("Query failed")
            .is_some(),
        "Recently deleted org should not be purged within retention period"
    );
}

#[test]
fn test_purge_respects_cascade_hierarchy() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Soft delete organization (cascades to all)
    queries::soft_delete_organization(&conn, &org.id).expect("Soft delete failed");

    // Set all to old timestamp
    let old_timestamp = now() - (100 * 86400);
    conn.execute(
        "UPDATE organizations SET deleted_at = ?1",
        rusqlite::params![old_timestamp],
    )
    .unwrap();
    conn.execute(
        "UPDATE projects SET deleted_at = ?1",
        rusqlite::params![old_timestamp],
    )
    .unwrap();
    conn.execute(
        "UPDATE products SET deleted_at = ?1",
        rusqlite::params![old_timestamp],
    )
    .unwrap();
    conn.execute(
        "UPDATE licenses SET deleted_at = ?1",
        rusqlite::params![old_timestamp],
    )
    .unwrap();

    // Purge
    let result = queries::purge_soft_deleted_records(&conn, ONE_MONTH).expect("Purge failed");

    // All should be purged
    assert!(result.licenses > 0, "Licenses should be purged");
    assert!(result.products > 0, "Products should be purged");
    assert!(result.projects > 0, "Projects should be purged");
    assert!(result.organizations > 0, "Organizations should be purged");

    // Verify nothing remains
    assert!(
        queries::get_deleted_license_by_id(&conn, &license.id)
            .expect("Query failed")
            .is_none(),
        "License should be completely removed after purge"
    );
    assert!(
        queries::get_deleted_product_by_id(&conn, &product.id)
            .expect("Query failed")
            .is_none(),
        "Product should be completely removed after purge"
    );
    assert!(
        queries::get_deleted_project_by_id(&conn, &project.id)
            .expect("Query failed")
            .is_none(),
        "Project should be completely removed after purge"
    );
    assert!(
        queries::get_deleted_organization_by_id(&conn, &org.id)
            .expect("Query failed")
            .is_none(),
        "Organization should be completely removed after purge"
    );
}

// ============ Hard Delete Tests ============

#[test]
fn test_hard_delete_user_completely_removes_all_data() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");
    let (user, _member, _api_key) =
        create_test_org_member(&conn, &org.id, "member@test.com", OrgMemberRole::Owner);

    // Hard delete the user
    queries::delete_user(&conn, &user.id).expect("Hard delete failed");

    // User should be completely gone (not even soft deleted)
    assert!(
        queries::get_user_by_id(&conn, &user.id)
            .expect("Query failed")
            .is_none(),
        "User should not be found via normal query after hard delete"
    );
    assert!(
        queries::get_deleted_user_by_id(&conn, &user.id)
            .expect("Query failed")
            .is_none(),
        "User should not be found via deleted query after hard delete"
    );
}

#[test]
fn test_hard_delete_organization_completely_removes_hierarchy() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Hard delete the organization
    queries::delete_organization(&conn, &org.id).expect("Hard delete failed");

    // Everything should be completely gone
    assert!(
        queries::get_organization_by_id(&conn, &org.id)
            .expect("Query failed")
            .is_none(),
        "Organization should not be found via normal query after hard delete"
    );
    assert!(
        queries::get_deleted_organization_by_id(&conn, &org.id)
            .expect("Query failed")
            .is_none(),
        "Organization should not be found via deleted query after hard delete"
    );
    assert!(
        queries::get_project_by_id(&conn, &project.id)
            .expect("Query failed")
            .is_none(),
        "Project should be cascade-deleted with organization"
    );
    assert!(
        queries::get_product_by_id(&conn, &product.id)
            .expect("Query failed")
            .is_none(),
        "Product should be cascade-deleted with organization"
    );
    assert!(
        queries::get_license_by_id(&conn, &license.id)
            .expect("Query failed")
            .is_none(),
        "License should be cascade-deleted with organization"
    );
}

// ============ Edge Cases ============

#[test]
fn test_soft_delete_already_deleted_item_is_idempotent() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // Soft delete twice
    queries::soft_delete_organization(&conn, &org.id).expect("First soft delete failed");
    let result = queries::soft_delete_organization(&conn, &org.id);

    // Should not error, but should not affect anything
    assert!(
        result.is_ok(),
        "Soft delete on already-deleted item should succeed (idempotent)"
    );
}

#[test]
fn test_restore_non_deleted_item_returns_false() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Test Org");

    // Try to restore a non-deleted org
    let result = queries::restore_organization(&conn, &org.id).expect("Query failed");

    // Should return false (nothing to restore)
    assert!(!result, "Restoring non-deleted item should return false");
}

#[test]
fn test_get_deleted_returns_none_for_active_item() {
    let conn = setup_test_db();
    let org = create_test_org(&conn, "Active Org");

    // get_deleted should return None for active (non-deleted) item
    let result = queries::get_deleted_organization_by_id(&conn, &org.id).expect("Query failed");
    assert!(
        result.is_none(),
        "get_deleted should return None for active item"
    );
}

#[test]
fn test_multiple_products_deleted_same_time_restore_correctly() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

    // Create multiple products
    let product1 = create_test_product(&conn, &project.id, "Product 1", "tier1");
    let product2 = create_test_product(&conn, &project.id, "Product 2", "tier2");
    let product3 = create_test_product(&conn, &project.id, "Product 3", "tier3");

    // Soft delete the project (cascades to all products at the same time)
    queries::soft_delete_project(&conn, &project.id).expect("Soft delete failed");

    // Verify all products are cascade-deleted
    assert!(
        queries::get_product_by_id(&conn, &product1.id)
            .expect("Query failed")
            .is_none(),
        "Product 1 should not be found after project soft delete"
    );
    assert!(
        queries::get_product_by_id(&conn, &product2.id)
            .expect("Query failed")
            .is_none(),
        "Product 2 should not be found after project soft delete"
    );
    assert!(
        queries::get_product_by_id(&conn, &product3.id)
            .expect("Query failed")
            .is_none(),
        "Product 3 should not be found after project soft delete"
    );

    // Restore the project
    queries::restore_project(&conn, &project.id, false).expect("Restore failed");

    // All products should be restored
    assert!(
        queries::get_product_by_id(&conn, &product1.id)
            .expect("Query failed")
            .is_some(),
        "Product 1 should be restored with project"
    );
    assert!(
        queries::get_product_by_id(&conn, &product2.id)
            .expect("Query failed")
            .is_some(),
        "Product 2 should be restored with project"
    );
    assert!(
        queries::get_product_by_id(&conn, &product3.id)
            .expect("Query failed")
            .is_some(),
        "Product 3 should be restored with project"
    );
}
