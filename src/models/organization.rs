use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result, msg};
use crate::models::project::{LemonSqueezyConfig, StripeConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub payment_provider: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrganization {
    pub name: String,
    /// User ID to create as owner of this org (must exist in users table)
    #[serde(default)]
    pub owner_user_id: Option<String>,
}

impl CreateOrganization {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(AppError::BadRequest(msg::NAME_EMPTY.into()));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganization {
    pub name: Option<String>,
    /// Stripe config - use Some(config) to set, Some(None) to clear, None to leave unchanged
    #[serde(default, deserialize_with = "deserialize_optional_stripe_config")]
    pub stripe_config: Option<Option<StripeConfig>>,
    /// LemonSqueezy config - use Some(config) to set, Some(None) to clear, None to leave unchanged
    #[serde(default, deserialize_with = "deserialize_optional_ls_config")]
    pub ls_config: Option<Option<LemonSqueezyConfig>>,
    /// Resend API key for email delivery (overrides system default)
    /// Use Some(None) to clear and fall back to system default, None to leave unchanged
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub resend_api_key: Option<Option<String>>,
    /// Payment provider ("stripe" or "lemonsqueezy")
    /// Use Some(None) to clear, None to leave unchanged
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub payment_provider: Option<Option<String>>,
}

impl UpdateOrganization {
    pub fn validate(&self) -> Result<()> {
        if let Some(ref name) = self.name
            && name.trim().is_empty()
        {
            return Err(AppError::BadRequest(msg::NAME_EMPTY.into()));
        }
        // payment_provider can be cleared with null, but if set it shouldn't be empty
        if let Some(Some(ref provider)) = self.payment_provider
            && provider.trim().is_empty()
        {
            return Err(AppError::BadRequest(
                "payment_provider cannot be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Deserialize a field that can be:
/// - absent (None) - leave unchanged
/// - null (Some(None)) - clear the value
/// - present (Some(Some(value))) - set to value
fn deserialize_optional_field<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}

fn deserialize_optional_stripe_config<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Option<StripeConfig>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}

fn deserialize_optional_ls_config<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Option<LemonSqueezyConfig>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}

/// Public view of an organization (includes configured services)
#[derive(Debug, Clone, Serialize)]
pub struct OrganizationPublic {
    pub id: String,
    pub name: String,
    /// Configured external services grouped by category
    /// e.g. { "payment": ["stripe", "lemonsqueezy"], "email": ["resend"] }
    pub configured_services: std::collections::HashMap<String, Vec<String>>,
    pub payment_provider: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

impl OrganizationPublic {
    /// Create OrganizationPublic with configured services map
    pub fn from_with_configs(
        org: Organization,
        configured_services: std::collections::HashMap<String, Vec<String>>,
    ) -> Self {
        Self {
            id: org.id,
            name: org.name,
            configured_services,
            payment_provider: org.payment_provider,
            created_at: org.created_at,
            updated_at: org.updated_at,
            deleted_at: org.deleted_at,
            deleted_cascade_depth: org.deleted_cascade_depth,
        }
    }
}
