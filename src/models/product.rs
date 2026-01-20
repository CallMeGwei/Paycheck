use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{AppError, Result, msg};

/// Deserialize a double Option field where:
/// - Field absent in JSON → None (don't update)
/// - Field present with null → Some(None) (set to NULL in DB)
/// - Field present with value → Some(Some(value)) (set to value)
fn deserialize_optional_nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    // This will be called only when the field is present in JSON
    // If present with null, we get None which we convert to Some(None)
    // If present with value, we get Some(value) which we convert to Some(Some(value))
    let value: Option<T> = Option::deserialize(deserializer)?;
    Ok(Some(value))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Product {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub tier: String,
    pub license_exp_days: Option<i32>,
    pub updates_exp_days: Option<i32>,
    /// Maximum number of activations allowed. None = unlimited.
    pub activation_limit: Option<i32>,
    /// Maximum number of concurrent devices. None = unlimited.
    pub device_limit: Option<i32>,
    /// Devices not seen for this many days don't count against device_limit.
    /// None = disabled (all devices count regardless of activity).
    pub device_inactive_days: Option<i32>,
    pub features: Vec<String>,
    /// Canonical price in cents (for display and future provider sync)
    pub price_cents: Option<i64>,
    /// Currency code (e.g., "usd")
    pub currency: Option<String>,
    pub created_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateProduct {
    pub name: String,
    pub tier: String,
    #[serde(default)]
    pub license_exp_days: Option<i32>,
    #[serde(default)]
    pub updates_exp_days: Option<i32>,
    /// Maximum number of activations allowed. None = unlimited.
    #[serde(default)]
    pub activation_limit: Option<i32>,
    /// Maximum number of concurrent devices. None = unlimited.
    #[serde(default)]
    pub device_limit: Option<i32>,
    #[serde(default)]
    pub device_inactive_days: Option<i32>,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub price_cents: Option<i64>,
    #[serde(default)]
    pub currency: Option<String>,
}

impl CreateProduct {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(AppError::BadRequest(msg::NAME_EMPTY.into()));
        }
        if self.tier.trim().is_empty() {
            return Err(AppError::BadRequest(msg::TIER_EMPTY.into()));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateProduct {
    pub name: Option<String>,
    pub tier: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    pub license_exp_days: Option<Option<i32>>,
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    pub updates_exp_days: Option<Option<i32>>,
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    pub activation_limit: Option<Option<i32>>,
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    pub device_limit: Option<Option<i32>>,
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    pub device_inactive_days: Option<Option<i32>>,
    pub features: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    pub price_cents: Option<Option<i64>>,
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    pub currency: Option<Option<String>>,
}

impl UpdateProduct {
    pub fn validate(&self) -> Result<()> {
        if let Some(ref name) = self.name
            && name.trim().is_empty()
        {
            return Err(AppError::BadRequest(msg::NAME_EMPTY.into()));
        }
        if let Some(ref tier) = self.tier
            && tier.trim().is_empty()
        {
            return Err(AppError::BadRequest(msg::TIER_EMPTY.into()));
        }
        Ok(())
    }
}
