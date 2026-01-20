mod from_row;
pub mod migrations;
pub mod queries;
mod schema;
pub mod soft_delete;

pub use migrations::{run_migrations, MigrationError, MigrationTarget};
pub use schema::{init_audit_db, init_db};

use std::sync::Arc;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::config::TrustedIssuer;
use crate::crypto::{EmailHasher, MasterKey};
use crate::email::EmailService;
use crate::jwt::JwksCache;
use crate::rate_limit::ActivationRateLimiter;

pub type DbPool = Pool<SqliteConnectionManager>;

/// Application state holding database pools and configuration
#[derive(Clone)]
pub struct AppState {
    /// Main database pool (operators, orgs, projects, licenses, etc.)
    pub db: DbPool,
    /// Audit log database pool (separate file to isolate growth)
    pub audit: DbPool,
    /// Base URL for callbacks (e.g., https://api.example.com)
    pub base_url: String,
    /// Whether audit logging is enabled
    pub audit_log_enabled: bool,
    /// Master key for envelope encryption of project private keys
    pub master_key: MasterKey,
    /// Email hasher with stable HMAC key (survives master key rotation)
    pub email_hasher: EmailHasher,
    /// URL for the success page after payment (when no project redirect is configured)
    pub success_page_url: String,
    /// Rate limiter for activation code requests (per email)
    pub activation_rate_limiter: Arc<ActivationRateLimiter>,
    /// Email service for sending activation codes
    pub email_service: Arc<EmailService>,
    /// Cache for JWKS from trusted issuers
    pub jwks_cache: Arc<JwksCache>,
    /// Trusted JWT issuers for first-party app authentication
    pub trusted_issuers: Vec<TrustedIssuer>,
}

pub fn create_pool(database_path: &str) -> Result<DbPool, r2d2::Error> {
    let manager = SqliteConnectionManager::file(database_path);
    Pool::builder().max_size(10).build(manager)
}
