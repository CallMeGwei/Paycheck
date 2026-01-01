use std::env;
use std::fs;
use std::path::Path;

use crate::crypto::MasterKey;

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_path: String,
    pub audit_database_path: String,
    pub base_url: String,
    pub bootstrap_operator_email: Option<String>,
    pub dev_mode: bool,
    /// Enable/disable audit logging entirely
    pub audit_log_enabled: bool,
    /// Days to retain audit logs before purging (0 = never purge)
    pub audit_log_retention_days: i64,
    /// Master key for envelope encryption of project private keys.
    /// Required in production; auto-generated in dev mode if not set.
    pub master_key: MasterKey,
}

/// Check that a file has secure permissions (owner read-only, no write, no group/other access).
/// Returns an error message if permissions are not exactly 0400.
#[cfg(unix)]
fn check_file_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path)
        .map_err(|e| format!("Failed to read file metadata: {}", e))?;

    let mode = metadata.permissions().mode() & 0o777;

    // Only accept 0400 (r--------) - read-only for owner, nothing else
    if mode != 0o400 {
        return Err(format!(
            "File permissions must be exactly 0400 (got: {:04o}). \
             Master key file must be read-only for owner with no group/other access.\n\
             Fix with: chmod 400 {}",
            mode,
            path.display()
        ));
    }

    Ok(())
}

#[cfg(not(unix))]
fn check_file_permissions(_path: &Path) -> Result<(), String> {
    // On non-Unix systems, we can't check permissions the same way.
    // Log a warning but proceed.
    eprintln!(
        "WARNING: Cannot verify file permissions on this platform. \
         Ensure the master key file is only readable by the service account."
    );
    Ok(())
}

/// Load the master key from a file, verifying permissions first.
/// Public so it can be used by the key rotation CLI command.
pub fn load_master_key_from_file(path: &str) -> Result<MasterKey, String> {
    let path = Path::new(path);

    if !path.exists() {
        return Err(format!("Master key file not found: {}", path.display()));
    }

    // Check permissions before reading
    check_file_permissions(path)?;

    // Read the file
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read master key file: {}", e))?;

    // Parse the key (trim whitespace/newlines)
    MasterKey::from_base64(contents.trim())
        .map_err(|e| format!("Invalid master key in file: {}", e))
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();

        let dev_mode = env::var("PAYCHECK_ENV")
            .map(|v| v == "dev" || v == "development")
            .unwrap_or(false);

        let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3000);

        let base_url = env::var("BASE_URL")
            .unwrap_or_else(|_| format!("http://{}:{}", host, port));

        let audit_log_enabled = env::var("AUDIT_LOG_ENABLED")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);

        let audit_log_retention_days: i64 = env::var("AUDIT_LOG_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(90);

        // Master key for envelope encryption - loaded from file with permission checks
        let master_key = match env::var("PAYCHECK_MASTER_KEY_FILE") {
            Ok(path) => load_master_key_from_file(&path).unwrap_or_else(|e| {
                panic!("Failed to load master key:\n{}", e);
            }),
            Err(_) if dev_mode => {
                // In dev mode, generate an ephemeral key and warn
                let generated = MasterKey::generate();
                eprintln!("============================================");
                eprintln!("WARNING: No PAYCHECK_MASTER_KEY_FILE set.");
                eprintln!("Using ephemeral key for dev mode.");
                eprintln!("Private keys will NOT be recoverable after restart!");
                eprintln!();
                eprintln!("For persistent dev usage, create a key file:");
                eprintln!("  openssl rand -base64 32 > /path/to/master.key");
                eprintln!("  chmod 400 /path/to/master.key");
                eprintln!("  export PAYCHECK_MASTER_KEY_FILE=/path/to/master.key");
                eprintln!("============================================");
                MasterKey::from_base64(&generated).unwrap()
            }
            Err(_) => {
                panic!(
                    "PAYCHECK_MASTER_KEY_FILE environment variable is required.\n\n\
                     Create a master key file:\n  \
                       openssl rand -base64 32 > /etc/paycheck/master.key\n  \
                       chmod 400 /etc/paycheck/master.key\n\n\
                     Then set the environment variable:\n  \
                       export PAYCHECK_MASTER_KEY_FILE=/etc/paycheck/master.key"
                );
            }
        };

        Self {
            host,
            port,
            database_path: env::var("DATABASE_PATH")
                .unwrap_or_else(|_| "paycheck.db".to_string()),
            audit_database_path: env::var("AUDIT_DATABASE_PATH")
                .unwrap_or_else(|_| "paycheck_audit.db".to_string()),
            base_url,
            bootstrap_operator_email: env::var("BOOTSTRAP_OPERATOR_EMAIL").ok(),
            dev_mode,
            audit_log_enabled,
            audit_log_retention_days,
            master_key,
        }
    }

    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
