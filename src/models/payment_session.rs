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
    pub created_at: i64,
    pub completed: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreatePaymentSession {
    pub product_id: String,
    pub device_id: String,
    pub device_type: DeviceType,
    /// Developer-managed customer identifier (flows through to license)
    #[serde(default)]
    pub customer_id: Option<String>,
}
