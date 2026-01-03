use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductPaymentConfig {
    pub id: String,
    pub product_id: String,
    pub provider: String, // "stripe" or "lemonsqueezy"
    pub stripe_price_id: Option<String>,
    pub price_cents: Option<i64>,
    pub currency: Option<String>,
    pub ls_variant_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreatePaymentConfig {
    pub provider: String,
    #[serde(default)]
    pub stripe_price_id: Option<String>,
    #[serde(default)]
    pub price_cents: Option<i64>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub ls_variant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePaymentConfig {
    pub stripe_price_id: Option<Option<String>>,
    pub price_cents: Option<Option<i64>>,
    pub currency: Option<Option<String>>,
    pub ls_variant_id: Option<Option<String>>,
}
