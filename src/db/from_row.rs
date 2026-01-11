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

pub const OPERATOR_COLS: &str = "id, email, name, role, external_user_id, created_at";

pub const ORGANIZATION_COLS: &str =
    "id, name, stripe_config, ls_config, resend_api_key, payment_provider, created_at, updated_at";

pub const ORG_MEMBER_COLS: &str = "id, org_id, email, name, role, external_user_id, created_at";

pub const ORG_MEMBER_API_KEY_COLS: &str = "id, org_member_id, name, key_prefix, key_hash, created_at, last_used_at, expires_at, revoked_at";

pub const OPERATOR_API_KEY_COLS: &str = "id, operator_id, name, key_prefix, key_hash, created_at, last_used_at, expires_at, revoked_at";

pub const PROJECT_COLS: &str = "id, org_id, name, license_key_prefix, private_key, public_key, redirect_url, email_from, email_enabled, email_webhook_url, created_at, updated_at";

pub const PROJECT_MEMBER_COLS: &str = "id, org_member_id, project_id, role, created_at";

pub const PRODUCT_COLS: &str = "id, project_id, name, tier, license_exp_days, updates_exp_days, activation_limit, device_limit, features, created_at";

pub const PAYMENT_CONFIG_COLS: &str = "id, product_id, provider, stripe_price_id, price_cents, currency, ls_variant_id, created_at, updated_at";

/// Columns for licenses table (no encryption - email_hash instead of key)
pub const LICENSE_COLS: &str = "id, email_hash, project_id, product_id, customer_id, activation_count, revoked, revoked_jtis, created_at, expires_at, updates_expires_at, payment_provider, payment_provider_customer_id, payment_provider_subscription_id, payment_provider_order_id";

pub const DEVICE_COLS: &str =
    "id, license_id, device_id, device_type, name, jti, activated_at, last_seen_at";

pub const PAYMENT_SESSION_COLS: &str = "id, product_id, customer_id, created_at, completed, license_id";

pub const ACTIVATION_CODE_COLS: &str =
    "id, code_hash, license_id, expires_at, used, created_at";

// ============ FromRow Implementations ============

impl FromRow for Operator {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Operator {
            id: row.get(0)?,
            email: row.get(1)?,
            name: row.get(2)?,
            role: row.get::<_, String>(3)?.parse::<OperatorRole>().unwrap(),
            external_user_id: row.get(4)?,
            created_at: row.get(5)?,
        })
    }
}

impl FromRow for Organization {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        // Read config data as raw bytes (encrypted)
        let stripe_data: Option<Vec<u8>> = row.get(2)?;
        let ls_data: Option<Vec<u8>> = row.get(3)?;
        let resend_data: Option<Vec<u8>> = row.get(4)?;
        Ok(Organization {
            id: row.get(0)?,
            name: row.get(1)?,
            stripe_config_encrypted: stripe_data,
            ls_config_encrypted: ls_data,
            resend_api_key_encrypted: resend_data,
            payment_provider: row.get(5)?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
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
            external_user_id: row.get(5)?,
            created_at: row.get(6)?,
        })
    }
}

impl FromRow for OrgMemberApiKey {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(OrgMemberApiKey {
            id: row.get(0)?,
            org_member_id: row.get(1)?,
            name: row.get(2)?,
            prefix: row.get(3)?,
            key_hash: row.get(4)?,
            created_at: row.get(5)?,
            last_used_at: row.get(6)?,
            expires_at: row.get(7)?,
            revoked_at: row.get(8)?,
        })
    }
}

impl FromRow for OperatorApiKey {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(OperatorApiKey {
            id: row.get(0)?,
            operator_id: row.get(1)?,
            name: row.get(2)?,
            prefix: row.get(3)?,
            key_hash: row.get(4)?,
            created_at: row.get(5)?,
            last_used_at: row.get(6)?,
            expires_at: row.get(7)?,
            revoked_at: row.get(8)?,
        })
    }
}

impl FromRow for Project {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Project {
            id: row.get(0)?,
            org_id: row.get(1)?,
            name: row.get(2)?,
            license_key_prefix: row.get(3)?,
            private_key: row.get(4)?,
            public_key: row.get(5)?,
            redirect_url: row.get(6)?,
            email_from: row.get(7)?,
            email_enabled: row.get::<_, i32>(8)? != 0,
            email_webhook_url: row.get(9)?,
            created_at: row.get(10)?,
            updated_at: row.get(11)?,
        })
    }
}

impl FromRow for ProjectMember {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(ProjectMember {
            id: row.get(0)?,
            org_member_id: row.get(1)?,
            project_id: row.get(2)?,
            role: row
                .get::<_, String>(3)?
                .parse::<ProjectMemberRole>()
                .unwrap(),
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
            role: row
                .get::<_, String>(3)?
                .parse::<ProjectMemberRole>()
                .unwrap(),
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

impl FromRow for ProductPaymentConfig {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(ProductPaymentConfig {
            id: row.get(0)?,
            product_id: row.get(1)?,
            provider: row.get(2)?,
            stripe_price_id: row.get(3)?,
            price_cents: row.get(4)?,
            currency: row.get(5)?,
            ls_variant_id: row.get(6)?,
            created_at: row.get(7)?,
            updated_at: row.get(8)?,
        })
    }
}

impl FromRow for License {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        let jtis_str: String = row.get(7)?;
        Ok(License {
            id: row.get(0)?,
            email_hash: row.get(1)?,
            project_id: row.get(2)?,
            product_id: row.get(3)?,
            customer_id: row.get(4)?,
            activation_count: row.get(5)?,
            revoked: row.get::<_, i32>(6)? != 0,
            revoked_jtis: serde_json::from_str(&jtis_str).unwrap_or_default(),
            created_at: row.get(8)?,
            expires_at: row.get(9)?,
            updates_expires_at: row.get(10)?,
            payment_provider: row.get(11)?,
            payment_provider_customer_id: row.get(12)?,
            payment_provider_subscription_id: row.get(13)?,
            payment_provider_order_id: row.get(14)?,
        })
    }
}

impl FromRow for Device {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Device {
            id: row.get(0)?,
            license_id: row.get(1)?,
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
            customer_id: row.get(2)?,
            created_at: row.get(3)?,
            completed: row.get::<_, i32>(4)? != 0,
            license_id: row.get(5)?,
        })
    }
}

impl FromRow for ActivationCode {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(ActivationCode {
            id: row.get(0)?,
            code: row.get(1)?,
            license_id: row.get(2)?,
            expires_at: row.get(3)?,
            used: row.get::<_, i32>(4)? != 0,
            created_at: row.get(5)?,
        })
    }
}
