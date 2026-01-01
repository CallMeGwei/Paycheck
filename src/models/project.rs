use serde::{Deserialize, Serialize};

use crate::crypto::MasterKey;
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeConfig {
    pub secret_key: String,
    pub publishable_key: String,
    pub webhook_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LemonSqueezyConfig {
    pub api_key: String,
    pub store_id: String,
    pub webhook_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub domain: String,
    pub license_key_prefix: String,
    /// Encrypted private key (envelope encryption with master key)
    #[serde(skip_serializing)]
    pub private_key: Vec<u8>,
    pub public_key: String,
    /// Encrypted Stripe config (None if not configured)
    #[serde(skip)]
    pub stripe_config_encrypted: Option<Vec<u8>>,
    /// Encrypted LemonSqueezy config (None if not configured)
    #[serde(skip)]
    pub ls_config_encrypted: Option<Vec<u8>>,
    pub default_provider: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Project {
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
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectPublic {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub domain: String,
    pub license_key_prefix: String,
    pub public_key: String,
    pub has_stripe: bool,
    pub has_lemonsqueezy: bool,
    pub default_provider: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<Project> for ProjectPublic {
    fn from(p: Project) -> Self {
        let has_stripe = p.has_stripe_config();
        let has_ls = p.has_ls_config();
        Self {
            id: p.id,
            org_id: p.org_id,
            name: p.name,
            domain: p.domain,
            license_key_prefix: p.license_key_prefix,
            public_key: p.public_key,
            has_stripe,
            has_lemonsqueezy: has_ls,
            default_provider: p.default_provider,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateProject {
    pub name: String,
    pub domain: String,
    #[serde(default = "default_prefix")]
    pub license_key_prefix: String,
}

fn default_prefix() -> String {
    "PC".to_string()
}

/// Masked Stripe config for display (hides sensitive parts of keys)
#[derive(Debug, Clone, Serialize)]
pub struct StripeConfigMasked {
    pub secret_key: String,
    pub publishable_key: String,
    pub webhook_secret: String,
}

impl From<&StripeConfig> for StripeConfigMasked {
    fn from(config: &StripeConfig) -> Self {
        Self {
            secret_key: mask_secret(&config.secret_key),
            publishable_key: config.publishable_key.clone(), // Publishable keys are public
            webhook_secret: mask_secret(&config.webhook_secret),
        }
    }
}

/// Masked LemonSqueezy config for display
#[derive(Debug, Clone, Serialize)]
pub struct LemonSqueezyConfigMasked {
    pub api_key: String,
    pub store_id: String,
    pub webhook_secret: String,
}

impl From<&LemonSqueezyConfig> for LemonSqueezyConfigMasked {
    fn from(config: &LemonSqueezyConfig) -> Self {
        Self {
            api_key: mask_secret(&config.api_key),
            store_id: config.store_id.clone(), // Store ID is not sensitive
            webhook_secret: mask_secret(&config.webhook_secret),
        }
    }
}

/// Mask a secret string, showing first 8 and last 4 characters
/// e.g., "sk_test_abc123xyz789" -> "sk_test_...9789"
fn mask_secret(s: &str) -> String {
    if s.len() <= 12 {
        // Too short to meaningfully mask
        return "*".repeat(s.len().min(8));
    }
    format!("{}...{}", &s[..8], &s[s.len() - 4..])
}

#[derive(Debug, Deserialize)]
pub struct UpdateProject {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub license_key_prefix: Option<String>,
    pub stripe_config: Option<StripeConfig>,
    pub ls_config: Option<LemonSqueezyConfig>,
    /// Default payment provider ("stripe" or "lemonsqueezy")
    /// Use Some(None) to clear, None to leave unchanged
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub default_provider: Option<Option<String>>,
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
