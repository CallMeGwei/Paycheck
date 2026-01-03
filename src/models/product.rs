use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Product {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub tier: String,
    pub license_exp_days: Option<i32>,
    pub updates_exp_days: Option<i32>,
    pub activation_limit: i32,
    pub device_limit: i32,
    pub features: Vec<String>,
    pub created_at: i64,
    // Payment provider config (set by dev in dashboard)
    pub stripe_price_id: Option<String>,
    pub price_cents: Option<i64>,
    pub currency: Option<String>,
    pub ls_variant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateProduct {
    pub name: String,
    pub tier: String,
    #[serde(default)]
    pub license_exp_days: Option<i32>,
    #[serde(default)]
    pub updates_exp_days: Option<i32>,
    #[serde(default)]
    pub activation_limit: i32,
    #[serde(default)]
    pub device_limit: i32,
    #[serde(default)]
    pub features: Vec<String>,
    // Payment provider config
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
pub struct UpdateProduct {
    pub name: Option<String>,
    pub tier: Option<String>,
    pub license_exp_days: Option<Option<i32>>,
    pub updates_exp_days: Option<Option<i32>>,
    pub activation_limit: Option<i32>,
    pub device_limit: Option<i32>,
    pub features: Option<Vec<String>>,
    // Payment provider config
    pub stripe_price_id: Option<Option<String>>,
    pub price_cents: Option<Option<i64>>,
    pub currency: Option<Option<String>>,
    pub ls_variant_id: Option<Option<String>>,
}
