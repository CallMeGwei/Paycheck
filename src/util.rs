//! Shared utility functions for the Paycheck application.

use axum::http::HeaderMap;
use rusqlite::Connection;

use crate::db::queries;
use crate::error::Result;
use crate::models::{ActorType, AuditAction, AuditLog, AuditLogNames, Product};

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
        Self::from_days(
            product.license_exp_days,
            product.updates_exp_days,
            base_time,
        )
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

/// Builder for creating audit log entries.
///
/// Provides a fluent API for constructing audit logs with named methods
/// instead of positional parameters.
///
/// # Example
/// ```ignore
/// AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
///     .actor(ActorType::User, Some(&user_id))
///     .action(AuditAction::CreateOrganization)
///     .resource("organization", &org.id)
///     .details(&serde_json::json!({ "name": org.name }))
///     .names(&ctx.audit_names().resource(org.name.clone()))
///     .save()?;
/// ```
pub struct AuditLogBuilder<'a> {
    conn: &'a Connection,
    enabled: bool,
    headers: &'a HeaderMap,
    actor_type: ActorType,
    user_id: Option<&'a str>,
    action: AuditAction,
    resource_type: &'a str,
    resource_id: &'a str,
    details: Option<&'a serde_json::Value>,
    org_id: Option<&'a str>,
    project_id: Option<&'a str>,
    names: AuditLogNames,
}

impl<'a> AuditLogBuilder<'a> {
    /// Create a new audit log builder with required parameters.
    pub fn new(conn: &'a Connection, enabled: bool, headers: &'a HeaderMap) -> Self {
        Self {
            conn,
            enabled,
            headers,
            actor_type: ActorType::System,
            user_id: None,
            action: AuditAction::CreateUser, // Placeholder, should always be set
            resource_type: "",
            resource_id: "",
            details: None,
            org_id: None,
            project_id: None,
            names: AuditLogNames::default(),
        }
    }

    /// Set the actor type and optional user ID.
    pub fn actor(mut self, actor_type: ActorType, user_id: Option<&'a str>) -> Self {
        self.actor_type = actor_type;
        self.user_id = user_id;
        self
    }

    /// Set the action being performed.
    pub fn action(mut self, action: AuditAction) -> Self {
        self.action = action;
        self
    }

    /// Set the resource type and ID being acted upon.
    pub fn resource(mut self, resource_type: &'a str, resource_id: &'a str) -> Self {
        self.resource_type = resource_type;
        self.resource_id = resource_id;
        self
    }

    /// Set optional details JSON.
    pub fn details(mut self, details: &'a serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Set the organization context.
    pub fn org(mut self, org_id: &'a str) -> Self {
        self.org_id = Some(org_id);
        self
    }

    /// Set the project context.
    pub fn project(mut self, project_id: &'a str) -> Self {
        self.project_id = Some(project_id);
        self
    }

    /// Set human-readable names for display.
    pub fn names(mut self, names: &AuditLogNames) -> Self {
        self.names = names.clone();
        self
    }

    /// Save the audit log entry to the database.
    pub fn save(self) -> Result<AuditLog> {
        let (ip, ua) = extract_request_info(self.headers);
        queries::create_audit_log(
            self.conn,
            self.enabled,
            self.actor_type,
            self.user_id,
            self.action.as_ref(),
            self.resource_type,
            self.resource_id,
            self.details,
            self.org_id,
            self.project_id,
            ip.as_deref(),
            ua.as_deref(),
            &self.names,
        )
    }
}

