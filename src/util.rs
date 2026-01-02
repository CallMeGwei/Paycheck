//! Shared utility functions for the Paycheck application.

use axum::http::HeaderMap;
use rusqlite::Connection;

use crate::db::queries;
use crate::error::Result;
use crate::models::{ActorType, AuditLog, Product};

const SECONDS_PER_DAY: i64 = 86400;

/// Calculated license expiration timestamps.
#[derive(Debug, Clone, Copy)]
pub struct LicenseExpirations {
    /// When the license expires (None = perpetual)
    pub license_exp: Option<i64>,
    /// When update access expires (None = perpetual)
    pub updates_exp: Option<i64>,
}

impl LicenseExpirations {
    /// Calculate expirations from a product's exp_days fields.
    ///
    /// `base_time` is typically `Utc::now().timestamp()` for new licenses,
    /// or `device.activated_at` for validation.
    pub fn from_product(product: &Product, base_time: i64) -> Self {
        Self::from_days(product.license_exp_days, product.updates_exp_days, base_time)
    }

    /// Calculate expirations from explicit day values.
    ///
    /// `base_time` is typically `Utc::now().timestamp()`.
    pub fn from_days(license_days: Option<i32>, updates_days: Option<i32>, base_time: i64) -> Self {
        Self {
            license_exp: license_days.map(|days| base_time + (days as i64) * SECONDS_PER_DAY),
            updates_exp: updates_days.map(|days| base_time + (days as i64) * SECONDS_PER_DAY),
        }
    }
}

/// Extract client IP address and user-agent from request headers.
///
/// Tries `x-forwarded-for` first (for proxied requests), then `x-real-ip`,
/// and extracts the `user-agent` header for audit logging.
pub fn extract_request_info(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    (ip, user_agent)
}

/// Extract a Bearer token from the Authorization header.
///
/// Returns the token string without the "Bearer " prefix, or None if
/// the header is missing, malformed, or empty after the prefix.
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}

/// Create an audit log entry, automatically extracting IP and user-agent from headers.
///
/// This is a thin wrapper around `queries::create_audit_log` that handles the
/// common pattern of extracting request info from headers.
#[allow(clippy::too_many_arguments)]
pub fn audit_log(
    conn: &Connection,
    enabled: bool,
    actor_type: ActorType,
    actor_id: Option<&str>,
    headers: &HeaderMap,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    details: Option<&serde_json::Value>,
    org_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<AuditLog> {
    let (ip, ua) = extract_request_info(headers);
    queries::create_audit_log(
        conn,
        enabled,
        actor_type,
        actor_id,
        action,
        resource_type,
        resource_id,
        details,
        org_id,
        project_id,
        ip.as_deref(),
        ua.as_deref(),
    )
}
