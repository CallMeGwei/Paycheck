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
}
