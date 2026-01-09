//! Error types for the Paycheck SDK

use thiserror::Error;

/// Error codes for Paycheck errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaycheckErrorCode {
    /// No token stored
    NoToken,
    /// Token's JWT exp has passed (try refresh)
    TokenExpired,
    /// License exp has passed
    LicenseExpired,
    /// License has been revoked
    LicenseRevoked,
    /// Cannot activate more devices
    DeviceLimitReached,
    /// Cannot activate license anymore
    ActivationLimitReached,
    /// License key not found
    InvalidLicenseKey,
    /// Redemption code invalid or expired
    InvalidCode,
    /// Network request failed
    NetworkError,
    /// Invalid request parameters
    ValidationError,
}

impl std::fmt::Display for PaycheckErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoToken => write!(f, "NO_TOKEN"),
            Self::TokenExpired => write!(f, "TOKEN_EXPIRED"),
            Self::LicenseExpired => write!(f, "LICENSE_EXPIRED"),
            Self::LicenseRevoked => write!(f, "LICENSE_REVOKED"),
            Self::DeviceLimitReached => write!(f, "DEVICE_LIMIT_REACHED"),
            Self::ActivationLimitReached => write!(f, "ACTIVATION_LIMIT_REACHED"),
            Self::InvalidLicenseKey => write!(f, "INVALID_LICENSE_KEY"),
            Self::InvalidCode => write!(f, "INVALID_CODE"),
            Self::NetworkError => write!(f, "NETWORK_ERROR"),
            Self::ValidationError => write!(f, "VALIDATION_ERROR"),
        }
    }
}

/// Paycheck SDK error
#[derive(Debug, Error)]
#[error("{message} (code: {code})")]
pub struct PaycheckError {
    /// Error code
    pub code: PaycheckErrorCode,
    /// Human-readable message
    pub message: String,
    /// HTTP status code (for API errors)
    pub status_code: Option<u16>,
}

impl PaycheckError {
    /// Create a new error
    pub fn new(code: PaycheckErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status_code: None,
        }
    }

    /// Create a new error with status code
    pub fn with_status(
        code: PaycheckErrorCode,
        message: impl Into<String>,
        status_code: u16,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            status_code: Some(status_code),
        }
    }

    /// Create a validation error
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(PaycheckErrorCode::ValidationError, message)
    }

    /// Create a network error
    pub fn network(message: impl Into<String>) -> Self {
        Self::new(PaycheckErrorCode::NetworkError, message)
    }

    /// Create a no token error
    pub fn no_token() -> Self {
        Self::new(PaycheckErrorCode::NoToken, "No token stored")
    }
}

/// Result type for Paycheck operations
pub type Result<T> = std::result::Result<T, PaycheckError>;

/// Map HTTP status code to error code
pub(crate) fn map_status_to_error_code(status: u16, message: &str) -> PaycheckErrorCode {
    let lower_message = message.to_lowercase();

    if status == 401 || status == 403 {
        if lower_message.contains("revoked") {
            return PaycheckErrorCode::LicenseRevoked;
        }
        if lower_message.contains("expired") {
            return PaycheckErrorCode::LicenseExpired;
        }
        if lower_message.contains("device limit") {
            return PaycheckErrorCode::DeviceLimitReached;
        }
        if lower_message.contains("activation limit") {
            return PaycheckErrorCode::ActivationLimitReached;
        }
        return PaycheckErrorCode::InvalidLicenseKey;
    }

    if status == 404 {
        if lower_message.contains("code") {
            return PaycheckErrorCode::InvalidCode;
        }
        return PaycheckErrorCode::InvalidLicenseKey;
    }

    if status == 400 {
        return PaycheckErrorCode::ValidationError;
    }

    PaycheckErrorCode::NetworkError
}
