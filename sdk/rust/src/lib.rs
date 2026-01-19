//! # Paycheck SDK
//!
//! Official Rust SDK for [Paycheck](https://paycheck.dev) -
//! the offline-first licensing system for indie developers.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use paycheck_sdk::{Paycheck, PaycheckOptions, DeviceType};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize with your project's public key
//!     let paycheck = Paycheck::new("your-base64-public-key", PaycheckOptions {
//!         base_url: Some("https://pay.myapp.com".into()),
//!         device_type: Some(DeviceType::Machine),
//!         ..Default::default()
//!     })?;
//!
//!     // Check if already licensed (works offline, verifies Ed25519 signature!)
//!     if paycheck.is_licensed() {
//!         println!("Licensed! Tier: {:?}", paycheck.get_tier());
//!         return Ok(());
//!     }
//!
//!     // Activate with code (from payment callback or email recovery)
//!     let result = paycheck.activate_with_code("MYAPP-AB3D-EF5G", None).await?;
//!     println!("Activated! Tier: {}", result.tier);
//!
//!     // Feature gating
//!     if paycheck.has_feature("export") {
//!         println!("Export feature enabled!");
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Features
//!
//! - `native-storage` (default): File-based storage in app data directory
//! - `native-tls` (default): Use native TLS for HTTPS
//! - `rustls-tls`: Use rustls for HTTPS (alternative to native-tls)
//!
//! ## Offline-First Design
//!
//! The SDK is designed for offline-first operation:
//!
//! - `is_licensed()`, `has_feature()`, `get_tier()` work without network
//! - Ed25519 signature verification ensures JWT authenticity offline
//! - License validity is checked via `license_exp` claim, not JWT `exp`
//! - Tokens auto-refresh when network is available
//! - JWTs can be refreshed up to 10 years after issuance

pub mod device;
pub mod error;
pub mod jwt;
pub mod paycheck;
pub mod storage;
pub mod types;

// Main client
pub use paycheck::{
    CheckoutOptions, ImportResult, OfflineValidateResult, Paycheck, PaycheckOptions, SyncResult,
    DEFAULT_BASE_URL,
};

// Error types
pub use error::{PaycheckError, PaycheckErrorCode, Result};

// Storage
pub use storage::{MemoryStorage, StorageAdapter};

// Types
pub use types::{
    ActivationResult, CallbackResult, CallbackStatus, CheckoutParams, CheckoutResult,
    DeactivateResult, DeviceInfo, DeviceType, LicenseClaims, LicenseDeviceInfo, LicenseInfo,
    LicenseStatus, RequestCodeResult, ValidateResult,
};

// Re-export storage implementations
#[cfg(feature = "native-storage")]
pub use storage::FileStorage;

// Re-export device utilities
pub use device::{generate_uuid, get_machine_id};

// Re-export JWT utilities
pub use jwt::{
    covers_version, decode_token, has_feature, is_jwt_expired, is_license_expired, verify_token,
    verify_and_decode_token,
};
