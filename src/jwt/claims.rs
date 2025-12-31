use serde::{Deserialize, Serialize};

/// Custom claims for Paycheck licenses (non-standard JWT claims)
/// Standard claims (iss, sub, aud, jti, iat, exp) are handled by jwt-simple
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
    // Paycheck-specific claims
    pub license_exp: Option<i64>,  // When license access ends (NULL = perpetual)
    pub updates_exp: Option<i64>,  // When new version access ends
    pub tier: String,              // Product tier
    pub features: Vec<String>,     // Enabled features

    // Identity
    pub device_id: String,         // Device identifier
    pub device_type: String,       // "uuid" or "machine"

    // Metadata
    pub product_id: String,        // Product ID
    pub license_key: String,       // License key for reference
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsBuilder {
    pub license_key_id: String,
    pub license_key: String,
    pub domain: String,
    pub device_id: String,
    pub device_type: String,
    pub tier: String,
    pub features: Vec<String>,
    pub product_id: String,
    pub license_exp_days: Option<i32>,
    pub updates_exp_days: Option<i32>,
}

impl ClaimsBuilder {
    pub fn build(self, now: i64) -> (LicenseClaims, String, String, String) {
        let license_exp = self.license_exp_days.map(|days| now + (days as i64 * 86400));
        let updates_exp = self.updates_exp_days.map(|days| now + (days as i64 * 86400));

        let claims = LicenseClaims {
            license_exp,
            updates_exp,
            tier: self.tier,
            features: self.features,
            device_id: self.device_id,
            device_type: self.device_type,
            product_id: self.product_id,
            license_key: self.license_key,
        };

        // Return custom claims + standard claim values (sub, aud, jti placeholder)
        (claims, self.license_key_id, self.domain, uuid::Uuid::new_v4().to_string())
    }
}
