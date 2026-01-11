use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumString};

/// Access level for API key scopes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsRefStr, EnumString)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum AccessLevel {
    View,
    Admin,
}

/// Unified API key (tied to user identity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub prefix: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    /// If false, key is Console-managed and hidden from user
    pub user_manageable: bool,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
}

/// API key scope - restricts what orgs/projects a key can access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyScope {
    pub api_key_id: String,
    pub org_id: String,
    /// If None, key has access to all projects in the org
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    pub access: AccessLevel,
}

/// Input for creating an API key
#[derive(Debug, Deserialize)]
pub struct CreateApiKey {
    pub name: String,
    /// Optional expiration in days from now
    #[serde(default)]
    pub expires_in_days: Option<i64>,
    /// Optional scopes to restrict access (null = full access)
    #[serde(default)]
    pub scopes: Option<Vec<CreateApiKeyScope>>,
    /// Operator-only: if false, key is hidden from user (Console-managed)
    #[serde(default)]
    pub user_manageable: Option<bool>,
}

/// Scope input when creating an API key
#[derive(Debug, Clone, Deserialize)]
pub struct CreateApiKeyScope {
    pub org_id: String,
    /// If None, access to all projects in the org
    #[serde(default)]
    pub project_id: Option<String>,
    pub access: AccessLevel,
}

/// Response when creating an API key (includes full key, shown only once)
#[derive(Debug, Serialize)]
pub struct ApiKeyCreated {
    pub id: String,
    pub name: String,
    /// Full API key - shown only on creation
    pub key: String,
    pub prefix: String,
    pub user_manageable: bool,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<ApiKeyScope>>,
}

/// Response when listing API keys (no full key)
#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub user_manageable: bool,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<ApiKeyScope>>,
}

impl From<ApiKey> for ApiKeyInfo {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id,
            name: key.name,
            prefix: key.prefix,
            user_manageable: key.user_manageable,
            created_at: key.created_at,
            last_used_at: key.last_used_at,
            expires_at: key.expires_at,
            scopes: None, // Scopes need to be loaded separately
        }
    }
}

/// Bulk revoke API keys request
#[derive(Debug, Deserialize)]
pub struct BulkRevokeApiKeys {
    pub key_ids: Vec<String>,
}

/// Bulk revoke API keys response
#[derive(Debug, Serialize)]
pub struct BulkRevokeApiKeysResponse {
    pub revoked: Vec<String>,
    pub errors: Vec<BulkRevokeError>,
}

#[derive(Debug, Serialize)]
pub struct BulkRevokeError {
    pub key_id: String,
    pub error: String,
}
