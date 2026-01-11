use serde::{Deserialize, Serialize};

use crate::crypto::MasterKey;
use crate::error::{AppError, Result};
use crate::models::project::{LemonSqueezyConfig, StripeConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    /// Encrypted Stripe config (None if not configured)
    #[serde(skip)]
    pub stripe_config_encrypted: Option<Vec<u8>>,
    /// Encrypted LemonSqueezy config (None if not configured)
    #[serde(skip)]
    pub ls_config_encrypted: Option<Vec<u8>>,
    /// Encrypted Resend API key (None if not configured - uses system default)
    #[serde(skip)]
    pub resend_api_key_encrypted: Option<Vec<u8>>,
    pub payment_provider: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Organization {
    /// Decrypt and parse the Stripe config.
    pub fn decrypt_stripe_config(&self, master_key: &MasterKey) -> Result<Option<StripeConfig>> {
        let Some(encrypted) = &self.stripe_config_encrypted else {
            return Ok(None);
        };

        let decrypted = master_key.decrypt_private_key(&self.id, encrypted)?;
        let json = String::from_utf8(decrypted)
            .map_err(|_| crate::error::AppError::Internal("Invalid UTF-8 in config".into()))?;
        let config: StripeConfig = serde_json::from_str(&json)?;
        Ok(Some(config))
    }

    /// Decrypt and parse the LemonSqueezy config.
    pub fn decrypt_ls_config(&self, master_key: &MasterKey) -> Result<Option<LemonSqueezyConfig>> {
        let Some(encrypted) = &self.ls_config_encrypted else {
            return Ok(None);
        };

        let decrypted = master_key.decrypt_private_key(&self.id, encrypted)?;
        let json = String::from_utf8(decrypted)
            .map_err(|_| crate::error::AppError::Internal("Invalid UTF-8 in config".into()))?;
        let config: LemonSqueezyConfig = serde_json::from_str(&json)?;
        Ok(Some(config))
    }

    /// Check if Stripe is configured (without decrypting).
    pub fn has_stripe_config(&self) -> bool {
        self.stripe_config_encrypted.is_some()
    }

    /// Check if LemonSqueezy is configured (without decrypting).
    pub fn has_ls_config(&self) -> bool {
        self.ls_config_encrypted.is_some()
    }

    /// Decrypt the Resend API key.
    pub fn decrypt_resend_api_key(&self, master_key: &MasterKey) -> Result<Option<String>> {
        let Some(encrypted) = &self.resend_api_key_encrypted else {
            return Ok(None);
        };

        let decrypted = master_key.decrypt_private_key(&self.id, encrypted)?;
        let api_key = String::from_utf8(decrypted)
            .map_err(|_| crate::error::AppError::Internal("Invalid UTF-8 in Resend API key".into()))?;
        Ok(Some(api_key))
    }

    /// Check if Resend is configured (without decrypting).
    pub fn has_resend_api_key(&self) -> bool {
        self.resend_api_key_encrypted.is_some()
    }
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
            return Err(AppError::BadRequest("name cannot be empty".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganization {
    pub name: Option<String>,
    pub stripe_config: Option<StripeConfig>,
    pub ls_config: Option<LemonSqueezyConfig>,
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
        if let Some(ref name) = self.name {
            if name.trim().is_empty() {
                return Err(AppError::BadRequest("name cannot be empty".into()));
            }
        }
        // payment_provider can be cleared with null, but if set it shouldn't be empty
        if let Some(Some(ref provider)) = self.payment_provider {
            if provider.trim().is_empty() {
                return Err(AppError::BadRequest("payment_provider cannot be empty".into()));
            }
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

/// Public view of an organization (includes payment config status)
#[derive(Debug, Clone, Serialize)]
pub struct OrganizationPublic {
    pub id: String,
    pub name: String,
    pub has_stripe: bool,
    pub has_lemonsqueezy: bool,
    pub has_resend: bool,
    pub payment_provider: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<Organization> for OrganizationPublic {
    fn from(o: Organization) -> Self {
        let has_stripe = o.has_stripe_config();
        let has_ls = o.has_ls_config();
        let has_resend = o.has_resend_api_key();
        Self {
            id: o.id,
            name: o.name,
            has_stripe,
            has_lemonsqueezy: has_ls,
            has_resend,
            payment_provider: o.payment_provider,
            created_at: o.created_at,
            updated_at: o.updated_at,
        }
    }
}
