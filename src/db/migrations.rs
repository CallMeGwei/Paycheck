//! Database migration system for Paycheck.
//!
//! Migrations are embedded in the binary and run automatically on startup.
//! Each database (main, audit) tracks its own version via `PRAGMA user_version`.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use thiserror::Error;

/// Target database for a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationTarget {
    /// Main database (paycheck.db)
    Main,
    /// Audit database (paycheck_audit.db)
    Audit,
}

impl MigrationTarget {
    /// Check if this target applies to the given database type.
    fn applies_to(self, target: MigrationTarget) -> bool {
        self == target
    }
}

/// A database migration.
pub struct Migration {
    /// Version number (sequential, starting from 1).
    pub version: i32,
    /// Human-readable description (include app version for traceability).
    pub description: &'static str,
    /// Target database.
    pub target: MigrationTarget,
    /// The migration function.
    pub up: fn(&Connection) -> rusqlite::Result<()>,
}

/// All migrations in order.
/// Add new migrations to the end of this list.
pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    description: "v0.3.0 baseline",
    target: MigrationTarget::Main,
    up: migration_001_baseline_main,
}, Migration {
    version: 1,
    description: "v0.3.0 baseline",
    target: MigrationTarget::Audit,
    up: migration_001_baseline_audit,
}];

/// Migration errors.
#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("Failed to create backup at {path}: {source}")]
    BackupFailed {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Migration {version} failed: {message}. Backup at: {backup_path}")]
    MigrationFailed {
        version: i32,
        message: String,
        backup_path: PathBuf,
    },

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Get the current schema version from the database.
pub fn get_version(conn: &Connection) -> rusqlite::Result<i32> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
}

/// Set the schema version in the database.
fn set_version(conn: &Connection, version: i32) -> rusqlite::Result<()> {
    conn.pragma_update(None, "user_version", version)
}

/// Create a backup of the database file before migration.
fn backup_database(db_path: &str, from_version: i32) -> Result<PathBuf, MigrationError> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let backup_path = PathBuf::from(format!("{}.backup_v{}_{}", db_path, from_version, timestamp));

    fs::copy(db_path, &backup_path).map_err(|e| MigrationError::BackupFailed {
        path: backup_path.clone(),
        source: e,
    })?;

    Ok(backup_path)
}

/// Clean up old backups, keeping only the most recent `keep_count`.
/// If `keep_count` is -1, keeps all backups. If 0, no backups were created.
fn cleanup_old_backups(db_path: &str, keep_count: i32) -> Result<(), std::io::Error> {
    if keep_count < 1 {
        return Ok(()); // -1 = keep all, 0 = no backups were created
    }
    let keep_count = keep_count as usize;

    let db_path = Path::new(db_path);
    let parent = db_path.parent().unwrap_or(Path::new("."));
    let db_name = db_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Find all backup files for this database
    let mut backups: Vec<_> = fs::read_dir(parent)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with(&format!("{}.backup_v", db_name)))
                .unwrap_or(false)
        })
        .collect();

    if backups.len() <= keep_count {
        return Ok(());
    }

    // Sort by modification time (oldest first)
    backups.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });

    // Remove oldest backups, keeping `keep_count`
    let to_remove = backups.len() - keep_count;
    for entry in backups.into_iter().take(to_remove) {
        tracing::info!("Removing old backup: {}", entry.path().display());
        fs::remove_file(entry.path())?;
    }

    Ok(())
}

/// Run pending migrations for a database.
///
/// - Checks current version via `PRAGMA user_version`
/// - Creates a backup before applying any migrations (unless `backup_keep_count` is 0)
/// - Runs each pending migration in its own transaction
/// - Cleans up old backups based on `backup_keep_count` (-1 = keep all)
pub fn run_migrations(
    conn: &mut Connection,
    db_path: &str,
    target: MigrationTarget,
    backup_keep_count: i32,
) -> Result<(), MigrationError> {
    let current_version = get_version(conn)?;

    // Filter migrations for this target that haven't been applied
    let pending: Vec<_> = MIGRATIONS
        .iter()
        .filter(|m| m.target.applies_to(target) && m.version > current_version)
        .collect();

    if pending.is_empty() {
        tracing::debug!(
            "{:?} database at version {} (up to date)",
            target,
            current_version
        );
        return Ok(());
    }

    tracing::info!(
        "{:?} database at version {}, {} migration(s) pending",
        target,
        current_version,
        pending.len()
    );

    // Backup before any changes (unless disabled with 0)
    let backup_path = if backup_keep_count == 0 {
        tracing::warn!("Migration backups disabled (MIGRATION_BACKUP_COUNT=0)");
        None
    } else {
        let path = backup_database(db_path, current_version)?;
        tracing::info!("Backup created: {}", path.display());
        Some(path)
    };

    // Run each migration in its own transaction
    for migration in pending {
        tracing::info!(
            "Running migration {}: {}",
            migration.version,
            migration.description
        );

        let tx = conn.transaction()?;

        match (migration.up)(&tx) {
            Ok(()) => {
                set_version(&tx, migration.version)?;
                tx.commit()?;
                tracing::info!("Migration {} completed", migration.version);
            }
            Err(e) => {
                // Transaction auto-rolls back on drop
                if let Some(ref path) = backup_path {
                    tracing::error!(
                        "Migration {} failed: {}. Database unchanged. Backup at: {}",
                        migration.version,
                        e,
                        path.display()
                    );
                } else {
                    tracing::error!(
                        "Migration {} failed: {}. Database unchanged. No backup available!",
                        migration.version,
                        e
                    );
                }
                return Err(MigrationError::MigrationFailed {
                    version: migration.version,
                    message: e.to_string(),
                    backup_path: backup_path.unwrap_or_default(),
                });
            }
        }
    }

    // Clean up old backups
    if let Err(e) = cleanup_old_backups(db_path, backup_keep_count) {
        tracing::warn!("Failed to clean up old backups: {}", e);
        // Non-fatal, continue
    }

    Ok(())
}

// ============================================================================
// Migration Functions
// ============================================================================

/// Migration 1: v0.3.0 baseline for main database.
///
/// This is the baseline migration. For existing databases, it's a no-op since
/// tables already exist. For fresh databases, the full schema is created by
/// `init_db` which runs after migrations.
fn migration_001_baseline_main(conn: &Connection) -> rusqlite::Result<()> {
    // Check if tables already exist (existing database)
    let tables_exist: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='users'",
        [],
        |row| row.get(0),
    )?;

    if tables_exist {
        // Existing database - init_db will handle schema (CREATE IF NOT EXISTS)
        tracing::debug!("Existing database detected, baseline migration is no-op");
        return Ok(());
    }

    // Fresh database - init_db will create schema after migrations complete
    tracing::debug!("Fresh database, schema will be created by init_db");
    Ok(())
}

/// Migration 1: v0.3.0 baseline for audit database.
fn migration_001_baseline_audit(conn: &Connection) -> rusqlite::Result<()> {
    // Check if tables already exist (existing database)
    let tables_exist: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='audit_logs'",
        [],
        |row| row.get(0),
    )?;

    if tables_exist {
        tracing::debug!("Existing audit database detected, baseline migration is no-op");
        return Ok(());
    }

    tracing::debug!("Fresh audit database, schema will be created by init_audit_db");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_get_set_version() {
        let conn = Connection::open_in_memory().unwrap();
        assert_eq!(get_version(&conn).unwrap(), 0);

        set_version(&conn, 5).unwrap();
        assert_eq!(get_version(&conn).unwrap(), 5);
    }

    #[test]
    fn test_migration_001_fresh_database() {
        let conn = Connection::open_in_memory().unwrap();
        migration_001_baseline_main(&conn).unwrap();
        // Should complete without error (no tables created - that's init_db's job)
    }

    #[test]
    fn test_migration_001_existing_database() {
        let conn = Connection::open_in_memory().unwrap();
        // Simulate existing database with users table
        conn.execute(
            "CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT)",
            [],
        )
        .unwrap();

        migration_001_baseline_main(&conn).unwrap();
        // Should complete without error (existing DB detected)
    }

    #[test]
    fn test_run_migrations_fresh_db() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path_str = db_path.to_str().unwrap();

        let mut conn = Connection::open(&db_path).unwrap();

        run_migrations(&mut conn, db_path_str, MigrationTarget::Main, 1).unwrap();

        // Should be at version 1
        assert_eq!(get_version(&conn).unwrap(), 1);

        // Backup should exist
        let backups: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".backup_v"))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(backups.len(), 1);
    }

    #[test]
    fn test_run_migrations_already_current() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path_str = db_path.to_str().unwrap();

        let mut conn = Connection::open(&db_path).unwrap();

        // Set version to current
        set_version(&conn, 1).unwrap();

        run_migrations(&mut conn, db_path_str, MigrationTarget::Main, 1).unwrap();

        // No backup should be created (no migrations ran)
        let backups: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".backup_v"))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(backups.len(), 0);
    }

    #[test]
    fn test_run_migrations_no_backup() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path_str = db_path.to_str().unwrap();

        let mut conn = Connection::open(&db_path).unwrap();

        // Run with backups disabled (0)
        run_migrations(&mut conn, db_path_str, MigrationTarget::Main, 0).unwrap();

        // Should still migrate
        assert_eq!(get_version(&conn).unwrap(), 1);

        // No backup should be created
        let backups: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".backup_v"))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(backups.len(), 0);
    }

    #[test]
    fn test_backup_cleanup() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path_str = db_path.to_str().unwrap();

        // Create some fake backup files
        for i in 0..5 {
            let backup_name = format!("test.db.backup_v0_2024010{}_120000", i);
            fs::write(dir.path().join(&backup_name), "test").unwrap();
            // Add small delay to ensure different modification times
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        cleanup_old_backups(db_path_str, 2).unwrap();

        let backups: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".backup_v"))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(backups.len(), 2);
    }

    #[test]
    fn test_backup_cleanup_keep_all() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path_str = db_path.to_str().unwrap();

        // Create some fake backup files
        for i in 0..5 {
            let backup_name = format!("test.db.backup_v0_2024010{}_120000", i);
            fs::write(dir.path().join(&backup_name), "test").unwrap();
        }

        // -1 = keep all
        cleanup_old_backups(db_path_str, -1).unwrap();

        let backups: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".backup_v"))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(backups.len(), 5); // All kept
    }
}
