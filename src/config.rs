use std::env;
use std::fs;
use std::path::Path;

use crate::crypto::MasterKey;

/// Configuration for a trusted JWT issuer (e.g., Console, mobile app).
/// JWTs from these issuers can authenticate to the API alongside API keys.
#[derive(Clone, Debug)]
pub struct TrustedIssuer {
    /// Issuer URL (must match `iss` claim in JWT)
    pub issuer: String,
    /// JWKS endpoint URL for fetching public keys
    pub jwks_url: String,
    /// Expected audience (must match `aud` claim in JWT)
    pub audience: String,
}

/// Rate limiting configuration for API endpoints
#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    /// Strict tier: requests per minute (for endpoints with external API calls like /buy)
    pub strict_rpm: u32,
    /// Standard tier: requests per minute (for most public endpoints)
    pub standard_rpm: u32,
    /// Relaxed tier: requests per minute (for lightweight endpoints like /health)
    pub relaxed_rpm: u32,
    /// Org ops tier: requests per minute (for /orgs/* authenticated endpoints)
    /// High limit to only stop extreme abuse (runaway scripts, DDoS attempts)
    pub org_ops_rpm: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            strict_rpm: 10,
            standard_rpm: 30,
            relaxed_rpm: 60,
            org_ops_rpm: 3000,
        }
    }
}

impl RateLimitConfig {
    /// Create a config with rate limiting disabled (for tests)
    pub fn disabled() -> Self {
        Self {
            strict_rpm: 0,
            standard_rpm: 0,
            relaxed_rpm: 0,
            org_ops_rpm: 0,
        }
    }
}

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
    /// Days to retain public (end-user) audit logs before purging.
    /// Internal actions (operator, org_member, system) are kept forever.
    /// 0 = never purge (default).
    pub public_audit_log_retention_days: i64,
    /// Days to retain soft-deleted records before permanent purge.
    /// 0 = never auto-purge (default). Must use explicit hard delete.
    pub soft_delete_retention_days: i64,
    /// Days to retain webhook events before purging.
    /// These are only used for replay attack prevention.
    /// Default: 30 days. 0 = never purge.
    pub webhook_event_retention_days: i64,
    /// Days to retain incomplete payment sessions before purging.
    /// Abandoned carts have no value after checkout expiry (~24h).
    /// Default: 7 days. 0 = never purge.
    pub payment_session_retention_days: i64,
    /// Master key for envelope encryption of project private keys.
    /// Required in production; auto-generated in dev mode if not set.
    pub master_key: MasterKey,
    /// URL for the success page after payment (when no project redirect is configured).
    /// If not set, defaults to {base_url}/success
    pub success_page_url: String,
    /// Rate limiting configuration for public endpoints
    pub rate_limit: RateLimitConfig,
    /// Allowed origins for admin console CORS (operator/org APIs)
    /// Set via PAYCHECK_CONSOLE_ORIGINS (comma-separated)
    pub console_origins: Vec<String>,
    /// System-level Resend API key for email delivery.
    /// Set via PAYCHECK_RESEND_API_KEY.
    /// Organizations can override with their own key; this is the fallback.
    pub resend_api_key: Option<String>,
    /// Default "from" email address for activation emails.
    /// Set via PAYCHECK_DEFAULT_FROM_EMAIL.
    /// Projects can override with their own email_from setting.
    pub default_from_email: String,
    /// Trusted JWT issuers for first-party app authentication.
    /// Set via PAYCHECK_TRUSTED_ISSUERS (JSON array).
    pub trusted_issuers: Vec<TrustedIssuer>,
    /// Number of database migration backups to keep.
    /// Set via MIGRATION_BACKUP_COUNT. Default: 3. -1 = keep all. 0 = no backups.
    pub migration_backup_count: i32,
}

/// Check that a file has secure permissions (owner read-only, no write, no group/other access).
/// Returns an error message if permissions are not exactly 0400.
#[cfg(unix)]
fn check_file_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata =
        fs::metadata(path).map_err(|e| format!("Failed to read file metadata: {}", e))?;

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
    let contents =
        fs::read_to_string(path).map_err(|e| format!("Failed to read master key file: {}", e))?;

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
            .unwrap_or(4242);

        let base_url = env::var("BASE_URL").unwrap_or_else(|_| format!("http://{}:{}", host, port));

        let audit_log_enabled = env::var("AUDIT_LOG_ENABLED")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);

        let public_audit_log_retention_days: i64 = env::var("PUBLIC_AUDIT_LOG_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let soft_delete_retention_days: i64 = env::var("SOFT_DELETE_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let webhook_event_retention_days: i64 = env::var("WEBHOOK_EVENT_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30); // Default 30 days - webhook events only needed for replay protection

        let payment_session_retention_days: i64 = env::var("PAYMENT_SESSION_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7); // Default 7 days - checkout sessions expire in ~24h

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

        let success_page_url = env::var("PAYCHECK_SUCCESS_PAGE_URL")
            .unwrap_or_else(|_| format!("{}/success", base_url));

        // Rate limiting configuration
        let rate_limit_defaults = RateLimitConfig::default();
        let rate_limit = RateLimitConfig {
            strict_rpm: env::var("RATE_LIMIT_STRICT_RPM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(rate_limit_defaults.strict_rpm),
            standard_rpm: env::var("RATE_LIMIT_STANDARD_RPM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(rate_limit_defaults.standard_rpm),
            relaxed_rpm: env::var("RATE_LIMIT_RELAXED_RPM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(rate_limit_defaults.relaxed_rpm),
            org_ops_rpm: env::var("RATE_LIMIT_ORG_OPS_RPM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(rate_limit_defaults.org_ops_rpm),
        };

        // Console origins for admin API CORS
        // In dev mode, defaults to localhost:3001 if not set
        let console_origins: Vec<String> = env::var("PAYCHECK_CONSOLE_ORIGINS")
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(|_| {
                if dev_mode {
                    vec![
                        "http://localhost:3001".to_string(),
                        "http://127.0.0.1:3001".to_string(),
                    ]
                } else {
                    vec![]
                }
            });

        // Resend API key for email delivery (optional - orgs can set their own)
        let resend_api_key = env::var("PAYCHECK_RESEND_API_KEY").ok();

        // Default "from" email address for activation emails
        let default_from_email = env::var("PAYCHECK_DEFAULT_FROM_EMAIL")
            .unwrap_or_else(|_| "noreply@paycheck.dev".to_string());

        // Trusted JWT issuers for first-party app authentication
        // Format: JSON array of {issuer, jwks_url, audience} objects
        let trusted_issuers: Vec<TrustedIssuer> = env::var("PAYCHECK_TRUSTED_ISSUERS")
            .ok()
            .and_then(|json| {
                #[derive(serde::Deserialize)]
                struct IssuerConfig {
                    issuer: String,
                    jwks_url: String,
                    audience: String,
                }
                serde_json::from_str::<Vec<IssuerConfig>>(&json)
                    .map_err(|e| {
                        eprintln!("WARNING: Failed to parse PAYCHECK_TRUSTED_ISSUERS: {}", e);
                        e
                    })
                    .ok()
            })
            .map(|configs| {
                configs
                    .into_iter()
                    .map(|c| TrustedIssuer {
                        issuer: c.issuer,
                        jwks_url: c.jwks_url,
                        audience: c.audience,
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Migration backup count (how many backups to keep)
        // -1 = keep all backups, 0 = no backups, n = keep n backups
        let migration_backup_count: i32 = env::var("MIGRATION_BACKUP_COUNT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);

        Self {
            host,
            port,
            database_path: env::var("DATABASE_PATH").unwrap_or_else(|_| "paycheck.db".to_string()),
            audit_database_path: env::var("AUDIT_DATABASE_PATH")
                .unwrap_or_else(|_| "paycheck_audit.db".to_string()),
            base_url,
            bootstrap_operator_email: env::var("BOOTSTRAP_OPERATOR_EMAIL").ok(),
            dev_mode,
            audit_log_enabled,
            public_audit_log_retention_days,
            soft_delete_retention_days,
            webhook_event_retention_days,
            payment_session_retention_days,
            master_key,
            success_page_url,
            rate_limit,
            console_origins,
            resend_api_key,
            default_from_email,
            trusted_issuers,
            migration_backup_count,
        }
    }

    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Creates a CORS layer for admin APIs (operator/org routes).
    /// Only allows requests from configured console origins.
    pub fn console_cors_layer(&self) -> tower_http::cors::CorsLayer {
        use axum::http::{HeaderName, HeaderValue, Method};
        use tower_http::cors::CorsLayer;

        let origins: Vec<HeaderValue> = self
            .console_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();

        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                HeaderName::from_static("authorization"),
                HeaderName::from_static("content-type"),
            ])
            .allow_credentials(true)
    }
}
