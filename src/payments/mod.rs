mod stripe;
mod lemonsqueezy;

pub use stripe::*;
pub use lemonsqueezy::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: String,
    pub provider: PaymentProvider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentProvider {
    Stripe,
    LemonSqueezy,
}

impl PaymentProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            PaymentProvider::Stripe => "stripe",
            PaymentProvider::LemonSqueezy => "lemonsqueezy",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "stripe" => Some(PaymentProvider::Stripe),
            "lemonsqueezy" | "ls" => Some(PaymentProvider::LemonSqueezy),
            _ => None,
        }
    }
}
