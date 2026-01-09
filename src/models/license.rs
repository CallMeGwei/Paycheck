use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub id: String,
    /// SHA-256 hash of the purchase email (no PII stored)
    pub email_hash: Option<String>,
    pub project_id: String,
    pub product_id: String,
    /// Developer-managed customer identifier (optional)
    /// Use this to link licenses to your own user/account system
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

#[derive(Debug, Clone, Serialize)]
pub struct LicenseWithProduct {
    #[serde(flatten)]
    pub license: License,
    pub product_name: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateLicense {
    /// SHA-256 hash of the purchase email (computed from webhook data)
    #[serde(default)]
    pub email_hash: Option<String>,
    /// Developer-managed customer identifier (optional)
    #[serde(default)]
    pub customer_id: Option<String>,
    pub expires_at: Option<i64>,
    pub updates_expires_at: Option<i64>,
    #[serde(default)]
    pub payment_provider: Option<String>,
    #[serde(default)]
    pub payment_provider_customer_id: Option<String>,
    #[serde(default)]
    pub payment_provider_subscription_id: Option<String>,
    #[serde(default)]
    pub payment_provider_order_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationCode {
    pub id: String,
    pub code: String,
    pub license_id: String,
    pub expires_at: i64,
    pub used: bool,
    pub created_at: i64,
}
