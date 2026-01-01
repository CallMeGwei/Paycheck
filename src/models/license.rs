use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseKey {
    pub id: String,
    pub key: String,
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
pub struct LicenseKeyWithProduct {
    #[serde(flatten)]
    pub license: LicenseKey,
    pub product_name: String,
    pub project_id: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateLicenseKey {
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
pub struct RedemptionCode {
    pub id: String,
    pub code: String,
    pub license_key_id: String,
    pub expires_at: i64,
    pub used: bool,
    pub created_at: i64,
}
