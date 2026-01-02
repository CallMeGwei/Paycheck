use serde::{Deserialize, Serialize};

/// Custom claims for Paycheck licenses (non-standard JWT claims)
/// Standard claims (iss, sub, aud, jti, iat, exp) are handled by jwt-simple
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
    // Paycheck-specific claims
    pub license_exp: Option<i64>, // When license access ends (NULL = perpetual)
    pub updates_exp: Option<i64>, // When new version access ends
    pub tier: String,             // Product tier
    pub features: Vec<String>,    // Enabled features

    // Identity
    pub device_id: String,   // Device identifier
    pub device_type: String, // "uuid" or "machine"

    // Metadata
    pub product_id: String, // Product ID
}

impl LicenseClaims {
    pub fn is_license_expired(&self, now: i64) -> bool {
        self.license_exp.is_some_and(|exp| now > exp)
    }

    pub fn covers_version(&self, version_timestamp: i64) -> bool {
        match self.updates_exp {
            Some(exp) => version_timestamp <= exp,
            None => true, // No updates expiration = covers all versions
        }
    }

    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
}
