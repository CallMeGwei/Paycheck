use serde::{Deserialize, Serialize};

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
    /// Allowlist of URLs that can be used as post-payment redirects
    pub allowed_redirect_urls: Vec<String>,
    /// Email "from" address for activation emails (e.g., "noreply@myapp.com")
    /// Falls back to system default if not set
    pub email_from: Option<String>,
    /// Whether email delivery is enabled for this project
    pub email_enabled: bool,
    /// Webhook URL to POST activation data to (instead of sending email)
    /// If set, Paycheck calls this URL and dev handles email delivery themselves
    pub email_webhook_url: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectPublic {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub domain: String,
    pub license_key_prefix: String,
    pub public_key: String,
    pub allowed_redirect_urls: Vec<String>,
    pub email_from: Option<String>,
    pub email_enabled: bool,
    pub email_webhook_url: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<Project> for ProjectPublic {
    fn from(p: Project) -> Self {
        Self {
            id: p.id,
            org_id: p.org_id,
            name: p.name,
            domain: p.domain,
            license_key_prefix: p.license_key_prefix,
            public_key: p.public_key,
            allowed_redirect_urls: p.allowed_redirect_urls,
            email_from: p.email_from,
            email_enabled: p.email_enabled,
            email_webhook_url: p.email_webhook_url,
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
    #[serde(default)]
    pub allowed_redirect_urls: Vec<String>,
    /// Email "from" address for activation emails (e.g., "noreply@myapp.com")
    #[serde(default)]
    pub email_from: Option<String>,
    /// Whether email delivery is enabled (default: true)
    #[serde(default = "default_email_enabled")]
    pub email_enabled: bool,
    /// Webhook URL to POST activation data to (instead of sending email)
    #[serde(default)]
    pub email_webhook_url: Option<String>,
}

fn default_prefix() -> String {
    "PC".to_string()
}

fn default_email_enabled() -> bool {
    true
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
    pub allowed_redirect_urls: Option<Vec<String>>,
    /// Email "from" address (use Some(None) to clear, None to leave unchanged)
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub email_from: Option<Option<String>>,
    /// Whether email delivery is enabled
    pub email_enabled: Option<bool>,
    /// Webhook URL (use Some(None) to clear, None to leave unchanged)
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub email_webhook_url: Option<Option<String>>,
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
