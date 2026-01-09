//! Type definitions for the Paycheck SDK

use serde::{Deserialize, Serialize};

/// Device type for license activation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    /// Random UUID (for web apps, browser-based)
    Uuid,
    /// Hardware-derived identifier (for desktop apps)
    Machine,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uuid => write!(f, "uuid"),
            Self::Machine => write!(f, "machine"),
        }
    }
}

/// Parameters for starting a checkout session.
///
/// Note: Price and variant info are configured in the product settings on Paycheck,
/// so you don't need to send them here - just the product ID.
#[derive(Debug, Clone, Default)]
pub struct CheckoutParams {
    /// Product UUID - Paycheck looks up pricing from product config
    pub product_id: String,
    /// Payment provider (auto-detected if not specified)
    pub provider: Option<String>,
    /// Your customer identifier (flows through to license)
    pub customer_id: Option<String>,
    /// Post-payment redirect URL (must be in project's allowlist)
    pub redirect: Option<String>,
}

/// Result from starting a checkout session
#[derive(Debug, Clone, Deserialize)]
pub struct CheckoutResult {
    /// URL to redirect user to
    pub checkout_url: String,
    /// Payment session ID
    pub session_id: String,
}

/// Result from parsing callback URL.
///
/// Note: No JWT is returned from callback - the user must call activate_with_code()
/// with their device info to get a JWT. This separates purchase from activation.
#[derive(Debug, Clone)]
pub struct CallbackResult {
    /// Payment status
    pub status: CallbackStatus,
    /// Short-lived activation code for URL-safe activation (PREFIX-XXXX-XXXX-XXXX-XXXX format)
    pub code: Option<String>,
    /// Project ID (needed for activation)
    pub project_id: Option<String>,
}

/// Payment callback status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackStatus {
    /// Payment successful
    Success,
    /// Payment pending
    Pending,
}

/// Optional device info for activation
#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    /// Human-readable device name
    pub device_name: Option<String>,
}

/// Result from license activation
#[derive(Debug, Clone)]
pub struct ActivationResult {
    /// JWT for this device
    pub token: String,
    /// When license expires (None = perpetual)
    pub license_exp: Option<i64>,
    /// When version access expires (None = all versions)
    pub updates_exp: Option<i64>,
    /// Product tier
    pub tier: String,
    /// Enabled features
    pub features: Vec<String>,
    /// Short-lived code for future activations (PREFIX-XXXX-XXXX-XXXX-XXXX format)
    pub activation_code: String,
    /// When activation code expires (30 minutes from creation)
    pub activation_code_expires_at: i64,
}

/// API response for redeem endpoints
#[derive(Debug, Deserialize)]
pub(crate) struct RedeemResponse {
    pub token: String,
    pub license_exp: Option<i64>,
    pub updates_exp: Option<i64>,
    pub tier: String,
    pub features: Vec<String>,
    pub activation_code: String,
    pub activation_code_expires_at: i64,
}

impl From<RedeemResponse> for ActivationResult {
    fn from(r: RedeemResponse) -> Self {
        Self {
            token: r.token,
            license_exp: r.license_exp,
            updates_exp: r.updates_exp,
            tier: r.tier,
            features: r.features,
            activation_code: r.activation_code,
            activation_code_expires_at: r.activation_code_expires_at,
        }
    }
}

/// Decoded JWT claims
#[derive(Debug, Clone, Deserialize)]
pub struct LicenseClaims {
    // Standard JWT claims
    /// Issuer ("paycheck")
    pub iss: String,
    /// Subject (license_id)
    pub sub: String,
    /// Audience (project domain)
    pub aud: String,
    /// JWT ID (unique per device activation)
    pub jti: String,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expires (Unix timestamp, ~1 hour)
    pub exp: i64,

    // Paycheck claims
    /// When license access ends (None = perpetual)
    pub license_exp: Option<i64>,
    /// When version access ends (None = all versions)
    pub updates_exp: Option<i64>,
    /// Product tier
    pub tier: String,
    /// Enabled features
    pub features: Vec<String>,
    /// Device identifier
    pub device_id: String,
    /// Device type
    pub device_type: DeviceType,
    /// Product UUID
    pub product_id: String,
}

/// Result from online validation
#[derive(Debug, Clone)]
pub struct ValidateResult {
    /// Whether the license is valid
    pub valid: bool,
    /// When license expires (if valid)
    pub license_exp: Option<i64>,
    /// When version access expires (if valid)
    pub updates_exp: Option<i64>,
}

/// API response for validate endpoint
#[derive(Debug, Deserialize)]
pub(crate) struct ValidateResponse {
    pub valid: bool,
    pub license_exp: Option<i64>,
    pub updates_exp: Option<i64>,
}

impl From<ValidateResponse> for ValidateResult {
    fn from(r: ValidateResponse) -> Self {
        Self {
            valid: r.valid,
            license_exp: r.license_exp,
            updates_exp: r.updates_exp,
        }
    }
}

/// Device info from license info endpoint
#[derive(Debug, Clone)]
pub struct LicenseDeviceInfo {
    pub device_id: String,
    pub device_type: DeviceType,
    pub name: Option<String>,
    pub activated_at: i64,
    pub last_seen_at: i64,
}

/// Full license information
#[derive(Debug, Clone)]
pub struct LicenseInfo {
    /// License status
    pub status: LicenseStatus,
    /// When license was created
    pub created_at: i64,
    /// When license expires (None = perpetual)
    pub expires_at: Option<i64>,
    /// When version access expires
    pub updates_expires_at: Option<i64>,
    /// Number of times license has been activated
    pub activation_count: i32,
    /// Maximum activations allowed
    pub activation_limit: i32,
    /// Current number of active devices
    pub device_count: i32,
    /// Maximum devices allowed
    pub device_limit: i32,
    /// Active devices
    pub devices: Vec<LicenseDeviceInfo>,
}

/// License status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseStatus {
    Active,
    Expired,
    Revoked,
}

/// API response for license info endpoint
#[derive(Debug, Deserialize)]
pub(crate) struct LicenseInfoResponse {
    pub status: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub updates_expires_at: Option<i64>,
    pub activation_count: i32,
    pub activation_limit: i32,
    pub device_count: i32,
    pub device_limit: i32,
    pub devices: Vec<LicenseDeviceInfoResponse>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LicenseDeviceInfoResponse {
    pub device_id: String,
    pub device_type: DeviceType,
    pub name: Option<String>,
    pub activated_at: i64,
    pub last_seen_at: i64,
}

impl From<LicenseInfoResponse> for LicenseInfo {
    fn from(r: LicenseInfoResponse) -> Self {
        let status = match r.status.as_str() {
            "active" => LicenseStatus::Active,
            "expired" => LicenseStatus::Expired,
            "revoked" => LicenseStatus::Revoked,
            _ => LicenseStatus::Expired,
        };

        Self {
            status,
            created_at: r.created_at,
            expires_at: r.expires_at,
            updates_expires_at: r.updates_expires_at,
            activation_count: r.activation_count,
            activation_limit: r.activation_limit,
            device_count: r.device_count,
            device_limit: r.device_limit,
            devices: r
                .devices
                .into_iter()
                .map(|d| LicenseDeviceInfo {
                    device_id: d.device_id,
                    device_type: d.device_type,
                    name: d.name,
                    activated_at: d.activated_at,
                    last_seen_at: d.last_seen_at,
                })
                .collect(),
        }
    }
}

/// Result from device deactivation
#[derive(Debug, Clone)]
pub struct DeactivateResult {
    /// Whether deactivation was successful
    pub deactivated: bool,
    /// Number of remaining active devices
    pub remaining_devices: i32,
}

/// API response for deactivate endpoint
#[derive(Debug, Deserialize)]
pub(crate) struct DeactivateResponse {
    pub deactivated: bool,
    pub remaining_devices: i32,
}

impl From<DeactivateResponse> for DeactivateResult {
    fn from(r: DeactivateResponse) -> Self {
        Self {
            deactivated: r.deactivated,
            remaining_devices: r.remaining_devices,
        }
    }
}
