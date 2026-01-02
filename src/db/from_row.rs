//! Row mapping trait and helpers for reducing boilerplate in queries.
//!
//! This module provides a `FromRow` trait that models can implement to
//! define how they are constructed from database rows, plus helper functions
//! for common query patterns.

use rusqlite::{Connection, OptionalExtension, Row, ToSql};

use crate::models::*;

/// Trait for constructing a type from a database row.
///
/// Implementing this trait allows using the `query_one` and `query_all`
/// helper functions, reducing repetitive row mapping closures.
pub trait FromRow: Sized {
    /// Construct an instance from a database row.
    fn from_row(row: &Row) -> rusqlite::Result<Self>;
}

/// Query for a single optional result.
pub fn query_one<T: FromRow>(
    conn: &Connection,
    sql: &str,
    params: &[&dyn ToSql],
) -> crate::error::Result<Option<T>> {
    conn.query_row(sql, params, T::from_row)
        .optional()
        .map_err(Into::into)
}

/// Query for multiple results.
pub fn query_all<T: FromRow>(
    conn: &Connection,
    sql: &str,
    params: &[&dyn ToSql],
) -> crate::error::Result<Vec<T>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt
        .query_map(params, T::from_row)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ============ SQL SELECT Constants ============

pub const OPERATOR_COLS: &str =
    "id, email, name, role, api_key_hash, created_at, created_by";

pub const ORGANIZATION_COLS: &str =
    "id, name, stripe_config, ls_config, default_provider, created_at, updated_at";

pub const ORG_MEMBER_COLS: &str =
    "id, org_id, email, name, role, api_key_hash, created_at";

pub const PROJECT_COLS: &str =
    "id, org_id, name, domain, license_key_prefix, private_key, public_key, allowed_redirect_urls, created_at, updated_at";

pub const PROJECT_MEMBER_COLS: &str =
    "id, org_member_id, project_id, role, created_at";

pub const PRODUCT_COLS: &str =
    "id, project_id, name, tier, license_exp_days, updates_exp_days, activation_limit, device_limit, features, created_at";

/// Columns for license_keys table.
/// Note: encrypted_key requires decryption with MasterKey, so use LicenseKeyRow
/// and decrypt manually rather than using the FromRow trait.
pub const LICENSE_KEY_COLS: &str =
    "id, key_hash, encrypted_key, project_id, product_id, customer_id, activation_count, revoked, revoked_jtis, created_at, expires_at, updates_expires_at, payment_provider, payment_provider_customer_id, payment_provider_subscription_id, payment_provider_order_id";

pub const DEVICE_COLS: &str =
    "id, license_key_id, device_id, device_type, name, jti, activated_at, last_seen_at";

pub const PAYMENT_SESSION_COLS: &str =
    "id, product_id, device_id, device_type, customer_id, redirect_url, created_at, completed, license_key_id";

pub const REDEMPTION_CODE_COLS: &str =
    "id, code_hash, license_key_id, expires_at, used, created_at";

// ============ FromRow Implementations ============

impl FromRow for Operator {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Operator {
            id: row.get(0)?,
            email: row.get(1)?,
            name: row.get(2)?,
            role: row.get::<_, String>(3)?.parse::<OperatorRole>().unwrap(),
            api_key_hash: row.get(4)?,
            created_at: row.get(5)?,
            created_by: row.get(6)?,
        })
    }
}

impl FromRow for Organization {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        // Read config data as raw bytes (encrypted)
        let stripe_data: Option<Vec<u8>> = row.get(2)?;
        let ls_data: Option<Vec<u8>> = row.get(3)?;
        Ok(Organization {
            id: row.get(0)?,
            name: row.get(1)?,
            stripe_config_encrypted: stripe_data,
            ls_config_encrypted: ls_data,
            default_provider: row.get(4)?,
            created_at: row.get(5)?,
            updated_at: row.get(6)?,
        })
    }
}

impl FromRow for OrgMember {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(OrgMember {
            id: row.get(0)?,
            org_id: row.get(1)?,
            email: row.get(2)?,
            name: row.get(3)?,
            role: row.get::<_, String>(4)?.parse::<OrgMemberRole>().unwrap(),
            api_key_hash: row.get(5)?,
            created_at: row.get(6)?,
        })
    }
}

impl FromRow for Project {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        let redirect_urls_str: String = row.get(7)?;
        Ok(Project {
            id: row.get(0)?,
            org_id: row.get(1)?,
            name: row.get(2)?,
            domain: row.get(3)?,
            license_key_prefix: row.get(4)?,
            private_key: row.get(5)?,
            public_key: row.get(6)?,
            allowed_redirect_urls: serde_json::from_str(&redirect_urls_str).unwrap_or_default(),
            created_at: row.get(8)?,
            updated_at: row.get(9)?,
        })
    }
}

impl FromRow for ProjectMember {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(ProjectMember {
            id: row.get(0)?,
            org_member_id: row.get(1)?,
            project_id: row.get(2)?,
            role: row.get::<_, String>(3)?.parse::<ProjectMemberRole>().unwrap(),
            created_at: row.get(4)?,
        })
    }
}

impl FromRow for ProjectMemberWithDetails {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(ProjectMemberWithDetails {
            id: row.get(0)?,
            org_member_id: row.get(1)?,
            project_id: row.get(2)?,
            role: row.get::<_, String>(3)?.parse::<ProjectMemberRole>().unwrap(),
            created_at: row.get(4)?,
            email: row.get(5)?,
            name: row.get(6)?,
        })
    }
}

impl FromRow for Product {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        let features_str: String = row.get(8)?;
        Ok(Product {
            id: row.get(0)?,
            project_id: row.get(1)?,
            name: row.get(2)?,
            tier: row.get(3)?,
            license_exp_days: row.get(4)?,
            updates_exp_days: row.get(5)?,
            activation_limit: row.get(6)?,
            device_limit: row.get(7)?,
            features: serde_json::from_str(&features_str).unwrap_or_default(),
            created_at: row.get(9)?,
        })
    }
}

/// Raw license key row from database, with encrypted key.
/// Use `decrypt_license_key_row` to convert to `LicenseKey`.
pub struct LicenseKeyRow {
    pub id: String,
    pub key_hash: String,
    pub encrypted_key: Vec<u8>,
    pub project_id: String,
    pub product_id: String,
    pub customer_id: Option<String>,
    pub activation_count: i32,
    pub revoked: bool,
    pub revoked_jtis: Vec<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub updates_expires_at: Option<i64>,
    pub payment_provider: Option<String>,
    pub payment_provider_customer_id: Option<String>,
    pub payment_provider_subscription_id: Option<String>,
    pub payment_provider_order_id: Option<String>,
}

impl FromRow for LicenseKeyRow {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        let jtis_str: String = row.get(8)?;
        Ok(LicenseKeyRow {
            id: row.get(0)?,
            key_hash: row.get(1)?,
            encrypted_key: row.get(2)?,
            project_id: row.get(3)?,
            product_id: row.get(4)?,
            customer_id: row.get(5)?,
            activation_count: row.get(6)?,
            revoked: row.get::<_, i32>(7)? != 0,
            revoked_jtis: serde_json::from_str(&jtis_str).unwrap_or_default(),
            created_at: row.get(9)?,
            expires_at: row.get(10)?,
            updates_expires_at: row.get(11)?,
            payment_provider: row.get(12)?,
            payment_provider_customer_id: row.get(13)?,
            payment_provider_subscription_id: row.get(14)?,
            payment_provider_order_id: row.get(15)?,
        })
    }
}

impl FromRow for Device {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Device {
            id: row.get(0)?,
            license_key_id: row.get(1)?,
            device_id: row.get(2)?,
            device_type: row.get::<_, String>(3)?.parse::<DeviceType>().unwrap(),
            name: row.get(4)?,
            jti: row.get(5)?,
            activated_at: row.get(6)?,
            last_seen_at: row.get(7)?,
        })
    }
}

impl FromRow for PaymentSession {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(PaymentSession {
            id: row.get(0)?,
            product_id: row.get(1)?,
            device_id: row.get(2)?,
            device_type: row.get::<_, String>(3)?.parse::<DeviceType>().unwrap(),
            customer_id: row.get(4)?,
            redirect_url: row.get(5)?,
            created_at: row.get(6)?,
            completed: row.get::<_, i32>(7)? != 0,
            license_key_id: row.get(8)?,
        })
    }
}

impl FromRow for RedemptionCode {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(RedemptionCode {
            id: row.get(0)?,
            code: row.get(1)?,
            license_key_id: row.get(2)?,
            expires_at: row.get(3)?,
            used: row.get::<_, i32>(4)? != 0,
            created_at: row.get(5)?,
        })
    }
}
