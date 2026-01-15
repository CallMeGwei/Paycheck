//! Soft-delete and restore helpers for reducing boilerplate in queries.
//!
//! This module provides reusable patterns for soft-delete operations:
//! - Setting `deleted_at` and `deleted_cascade_depth`
//! - Cascading deletes to child tables
//! - Restoring with force flag for cascaded items
//! - Purging old soft-deleted records
//!
//! # Cascade Hierarchy
//!
//! ```text
//! users (root)
//! ├── operators (depth 1)
//! └── org_members (depth 1)
//!
//! organizations (root)
//! ├── org_members (depth 1)
//! ├── projects (depth 1)
//! │   ├── products (depth 2)
//! │   └── licenses (depth 3)
//! └── (products/licenses via transitive cascade)
//!
//! projects (can be deleted directly)
//! ├── products (depth 1)
//! └── licenses (depth 2)
//!
//! products (can be deleted directly)
//! └── licenses (depth 1)
//!
//! operators, org_members, licenses are leaf entities (no children)
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};

use crate::error::{AppError, Result};

/// Get current Unix timestamp in seconds.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Result of a soft-delete operation.
pub struct SoftDeleteResult {
    /// Whether the entity was found and deleted
    pub deleted: bool,
    /// The timestamp used for this delete (for cascade matching)
    pub deleted_at: i64,
}

/// Soft-delete an entity by ID.
///
/// Sets `deleted_at` to current timestamp and `deleted_cascade_depth` to 0.
/// Returns `SoftDeleteResult` with the timestamp for use in cascade operations.
pub fn soft_delete_entity(conn: &Connection, table: &str, id: &str) -> Result<SoftDeleteResult> {
    let now = now();
    let sql = format!(
        "UPDATE {} SET deleted_at = ?1, deleted_cascade_depth = 0 WHERE id = ?2 AND deleted_at IS NULL",
        table
    );
    let updated = conn.execute(&sql, params![now, id])?;
    Ok(SoftDeleteResult {
        deleted: updated > 0,
        deleted_at: now,
    })
}

/// Cascade soft-delete to a child table via a direct foreign key.
///
/// Sets `deleted_at` and `deleted_cascade_depth` on all matching rows.
pub fn cascade_delete_direct(
    conn: &Connection,
    child_table: &str,
    fk_column: &str,
    parent_id: &str,
    deleted_at: i64,
    depth: i32,
) -> Result<usize> {
    let sql = format!(
        "UPDATE {} SET deleted_at = ?1, deleted_cascade_depth = ?2 WHERE {} = ?3 AND deleted_at IS NULL",
        child_table, fk_column
    );
    let updated = conn.execute(&sql, params![deleted_at, depth, parent_id])?;
    Ok(updated)
}

/// Cascade soft-delete to a child table via a subquery (for transitive relationships).
///
/// Example: Delete products where `project_id IN (SELECT id FROM projects WHERE org_id = ?)`
pub fn cascade_delete_via_subquery(
    conn: &Connection,
    child_table: &str,
    fk_column: &str,
    subquery: &str,
    parent_id: &str,
    deleted_at: i64,
    depth: i32,
) -> Result<usize> {
    let sql = format!(
        "UPDATE {} SET deleted_at = ?1, deleted_cascade_depth = ?2 WHERE {} IN ({}) AND deleted_at IS NULL",
        child_table, fk_column, subquery
    );
    let updated = conn.execute(&sql, params![deleted_at, depth, parent_id])?;
    Ok(updated)
}

/// Check if a restore should be allowed based on cascade depth.
///
/// Returns `Err` if the entity was cascade-deleted and `force` is false.
pub fn check_restore_allowed(
    cascade_depth: Option<i32>,
    force: bool,
    entity_name: &str,
) -> Result<()> {
    if cascade_depth.unwrap_or(0) > 0 && !force {
        return Err(AppError::BadRequest(format!(
            "{} was deleted via cascade. Use force=true or restore the parent entity first.",
            entity_name
        )));
    }
    Ok(())
}

/// Restore cascaded children in a child table via direct foreign key.
///
/// Only restores rows that match the parent's `deleted_at` timestamp and have `depth > 0`.
pub fn restore_cascaded_direct(
    conn: &Connection,
    child_table: &str,
    fk_column: &str,
    parent_id: &str,
    deleted_at: i64,
) -> Result<usize> {
    let sql = format!(
        "UPDATE {} SET deleted_at = NULL, deleted_cascade_depth = NULL \
         WHERE {} = ?1 AND deleted_at = ?2 AND deleted_cascade_depth > 0",
        child_table, fk_column
    );
    let updated = conn.execute(&sql, params![parent_id, deleted_at])?;
    Ok(updated)
}

/// Restore cascaded children in a child table via subquery (for transitive relationships).
pub fn restore_cascaded_via_subquery(
    conn: &Connection,
    child_table: &str,
    fk_column: &str,
    subquery: &str,
    parent_id: &str,
    deleted_at: i64,
) -> Result<usize> {
    let sql = format!(
        "UPDATE {} SET deleted_at = NULL, deleted_cascade_depth = NULL \
         WHERE {} IN ({}) AND deleted_at = ?2 AND deleted_cascade_depth > 0",
        child_table, fk_column, subquery
    );
    let updated = conn.execute(&sql, params![parent_id, deleted_at])?;
    Ok(updated)
}

/// Restore the entity itself (clear deleted_at and deleted_cascade_depth).
pub fn restore_entity(conn: &Connection, table: &str, id: &str) -> Result<usize> {
    let sql = format!(
        "UPDATE {} SET deleted_at = NULL, deleted_cascade_depth = NULL WHERE id = ?1",
        table
    );
    let updated = conn.execute(&sql, params![id])?;
    Ok(updated)
}

/// Purge (hard-delete) soft-deleted records older than the cutoff timestamp.
pub fn purge_table(conn: &Connection, table: &str, cutoff: i64) -> Result<usize> {
    let sql = format!(
        "DELETE FROM {} WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
        table
    );
    let deleted = conn.execute(&sql, params![cutoff])?;
    Ok(deleted)
}

/// Subquery for cascade DELETE: finds projects in an organization.
/// Uses ?3 because it's combined with UPDATE SET deleted_at = ?1, depth = ?2, org_id = ?3
pub const PROJECTS_IN_ORG_DELETE_SUBQUERY: &str = "SELECT id FROM projects WHERE org_id = ?3";

/// Subquery for cascade RESTORE: finds projects in an organization.
/// Uses ?1 because it's combined with org_id = ?1, deleted_at = ?2
pub const PROJECTS_IN_ORG_RESTORE_SUBQUERY: &str = "SELECT id FROM projects WHERE org_id = ?1";

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE parent (id TEXT PRIMARY KEY, deleted_at INTEGER, deleted_cascade_depth INTEGER);
             CREATE TABLE child (id TEXT PRIMARY KEY, parent_id TEXT, deleted_at INTEGER, deleted_cascade_depth INTEGER);
             INSERT INTO parent VALUES ('p1', NULL, NULL);
             INSERT INTO child VALUES ('c1', 'p1', NULL, NULL);
             INSERT INTO child VALUES ('c2', 'p1', NULL, NULL);",
        )
        .unwrap();
        conn
    }

    #[test]
    fn test_soft_delete_entity() {
        let conn = setup_test_db();
        let result = soft_delete_entity(&conn, "parent", "p1").unwrap();
        assert!(result.deleted);
        assert!(result.deleted_at > 0);

        // Verify entity is marked deleted
        let deleted_at: Option<i64> = conn
            .query_row("SELECT deleted_at FROM parent WHERE id = 'p1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(deleted_at.is_some());
    }

    #[test]
    fn test_cascade_delete_direct() {
        let conn = setup_test_db();
        let result = soft_delete_entity(&conn, "parent", "p1").unwrap();
        let cascaded =
            cascade_delete_direct(&conn, "child", "parent_id", "p1", result.deleted_at, 1).unwrap();
        assert_eq!(cascaded, 2);

        // Verify children are marked deleted with depth 1
        let depth: i32 = conn
            .query_row(
                "SELECT deleted_cascade_depth FROM child WHERE id = 'c1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(depth, 1);
    }

    #[test]
    fn test_restore_cascaded_direct() {
        let conn = setup_test_db();
        let result = soft_delete_entity(&conn, "parent", "p1").unwrap();
        cascade_delete_direct(&conn, "child", "parent_id", "p1", result.deleted_at, 1).unwrap();

        // Restore children
        let restored =
            restore_cascaded_direct(&conn, "child", "parent_id", "p1", result.deleted_at).unwrap();
        assert_eq!(restored, 2);

        // Verify children are restored
        let deleted_at: Option<i64> = conn
            .query_row("SELECT deleted_at FROM child WHERE id = 'c1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(deleted_at.is_none());
    }

    #[test]
    fn test_check_restore_allowed_direct_delete() {
        // Depth 0 (direct delete) should always be allowed
        assert!(check_restore_allowed(Some(0), false, "Test").is_ok());
        assert!(check_restore_allowed(None, false, "Test").is_ok());
    }

    #[test]
    fn test_check_restore_allowed_cascade_without_force() {
        // Depth > 0 without force should fail
        let result = check_restore_allowed(Some(1), false, "Test");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_restore_allowed_cascade_with_force() {
        // Depth > 0 with force should be allowed
        assert!(check_restore_allowed(Some(1), true, "Test").is_ok());
        assert!(check_restore_allowed(Some(3), true, "Test").is_ok());
    }
}
