use serde::{Deserialize, Serialize};

use super::DeviceType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentSession {
    pub id: String,
    pub product_id: String,
    pub device_id: String,
    pub device_type: DeviceType,
    /// Developer-managed customer identifier (flows through to license)
    pub customer_id: Option<String>,
    /// Validated redirect URL (from project's allowlist)
    pub redirect_url: Option<String>,
    pub created_at: i64,
    pub completed: bool,
    /// License key ID created by webhook (set when checkout completes)
    pub license_key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePaymentSession {
    pub product_id: String,
    pub device_id: String,
    pub device_type: DeviceType,
    /// Developer-managed customer identifier (flows through to license)
    #[serde(default)]
    pub customer_id: Option<String>,
    /// Validated redirect URL (must be in project's allowed_redirect_urls)
    #[serde(default)]
    pub redirect_url: Option<String>,
}
