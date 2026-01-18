# Paycheck Rust SDK

Official Rust SDK for [Paycheck](https://paycheck.dev) - the offline-first licensing system for indie developers.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
paycheck-sdk = "0.2"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Quick Start

```rust
use paycheck_sdk::{Paycheck, PaycheckOptions, DeviceType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize with your project's public key from the Paycheck dashboard
    let paycheck = Paycheck::new("your-base64-public-key", Default::default())?;

    // Or with options
    let paycheck = Paycheck::new("your-base64-public-key", PaycheckOptions {
        base_url: Some("https://pay.myapp.com".into()),
        device_type: Some(DeviceType::Machine),
        ..Default::default()
    })?;

    // Validate license (verifies Ed25519 signature offline!)
    let result = paycheck.validate(None);
    if result.valid {
        println!("Licensed! Tier: {:?}", result.claims.unwrap().tier);
        return Ok(());
    }

    // Activate with license key
    let result = paycheck.activate("PC-XXXXX-XXXXX", None).await?;
    println!("Activated! Features: {:?}", result.features);

    // Feature gating
    if paycheck.has_feature("export") {
        // Enable export functionality
    }

    Ok(())
}
```

## Features

### Crate Features

- `native-storage` (default): File-based storage in app data directory
- `native-tls` (default): Use native TLS for HTTPS
- `rustls-tls`: Use rustls for HTTPS (alternative to native-tls)

### Device Types

- `DeviceType::Machine`: Hardware-derived identifier (recommended for desktop apps)
  - Linux: `/etc/machine-id`
  - macOS: IOPlatformSerialNumber
  - Windows: Registry MachineGuid
- `DeviceType::Uuid`: Random UUID (for apps that don't need hardware binding)

## API Reference

### Configuration

```rust
let paycheck = Paycheck::new(public_key: &str, options: PaycheckOptions)?;

pub struct PaycheckOptions {
    /// Paycheck server URL (default: "https://api.paycheck.dev")
    pub base_url: Option<String>,
    /// Custom storage adapter (default: MemoryStorage)
    pub storage: Option<Arc<dyn StorageAdapter>>,
    /// Device type (default: Machine)
    pub device_type: Option<DeviceType>,
    /// Override device ID
    pub device_id: Option<String>,
    /// Auto-refresh expired tokens (default: true)
    pub auto_refresh: Option<bool>,
}
```

### Payment Flow

```rust
// Start checkout
let result = paycheck.checkout("product-uuid", None).await?;
println!("Redirect to: {}", result.checkout_url);

// With options
let result = paycheck.checkout("product-uuid", Some(CheckoutOptions {
    customer_id: Some("customer-123".into()),
    redirect: Some("https://myapp.com/callback".into()),
    ..Default::default()
})).await?;

// Parse callback (after payment redirect)
let result = paycheck.handle_callback("https://myapp.com/callback?license_key=xxx")?;
if result.status == CallbackStatus::Success {
    if let Some(key) = result.license_key {
        paycheck.activate(&key, None).await?;
    }
}
```

### Activation

```rust
// Activate with license key
let result = paycheck.activate("PC-XXXXX", None).await?;

// Activate with redemption code
let result = paycheck.activate_with_code("short-code", None).await?;

// With device name
let result = paycheck.activate("PC-XXXXX", Some(DeviceInfo {
    device_name: Some("John's MacBook".into()),
})).await?;

// Offline activation - import JWT directly (clipboard, QR code, etc.)
let result = paycheck.import_token(&jwt);
if result.valid {
    println!("Activated offline! Tier: {}", result.claims.unwrap().tier);
}
```

### Validation (with Ed25519 signature verification)

```rust
// Offline validation - verifies signature locally!
let result = paycheck.validate(None);
if result.valid {
    println!("Valid! Tier: {}", result.claims.unwrap().tier);
} else {
    println!("Invalid: {:?}", result.reason);
}

// Quick check
if paycheck.is_licensed() {
    println!("Has valid, signature-verified license");
}

// Sync with server (for subscription apps)
// Checks for updates, refreshes token if needed, falls back to offline
let result = paycheck.sync().await;
if result.valid {
    if result.offline {
        println!("Offline mode - using cached license");
    }
    println!("Tier: {}", result.claims.unwrap().tier);
} else if !result.synced {
    println!("Please connect to verify your license");
}

// Online validation (also checks revocation)
let result = paycheck.validate_online().await?;
if result.valid {
    println!("License is valid online");
}
```

### Token Operations

```rust
// Get stored token
let token = paycheck.get_token();

// Refresh expired token
let new_token = paycheck.refresh_token().await?;

// Clear stored token
paycheck.clear_token();
```

### Quick License Queries

```rust
// Sync convenience methods - use after validate()

if let Some(claims) = paycheck.get_license() {
    println!("Tier: {}", claims.tier);
    println!("Features: {:?}", claims.features);
}

if paycheck.has_feature("export") {
    // Enable export
}

if let Some(tier) = paycheck.get_tier() {
    println!("Current tier: {}", tier);
}

if paycheck.is_expired() {
    println!("License has expired");
}

// Check if a version is covered
let version_timestamp = 1704067200; // Jan 1, 2024
if paycheck.covers_version(version_timestamp) {
    println!("This version is covered");
}
```

### Online Operations

```rust
// Get full license info
let info = paycheck.get_license_info().await?;
println!("Devices: {}/{}", info.device_count, info.device_limit);

// Deactivate current device
let result = paycheck.deactivate().await?;
println!("Remaining devices: {}", result.remaining_devices);
```

## Custom Storage

```rust
use paycheck_sdk::{StorageAdapter, Paycheck, PaycheckOptions};
use std::sync::Arc;

struct MyStorage { /* ... */ }

impl StorageAdapter for MyStorage {
    fn get(&self, key: &str) -> Option<String> { /* ... */ }
    fn set(&self, key: &str, value: &str) { /* ... */ }
    fn remove(&self, key: &str) { /* ... */ }
}

let paycheck = Paycheck::new("your-public-key", PaycheckOptions {
    storage: Some(Arc::new(MyStorage::new())),
    ..Default::default()
})?;
```

### File Storage (Desktop Apps)

```rust
use paycheck_sdk::{FileStorage, Paycheck, PaycheckOptions};
use std::sync::Arc;

// Stores in:
// - Linux: ~/.local/share/myapp/paycheck.json
// - macOS: ~/Library/Application Support/myapp/paycheck.json
// - Windows: C:\Users\{User}\AppData\Roaming\myapp\paycheck.json
let storage = FileStorage::new("myapp").expect("Failed to create storage");

let paycheck = Paycheck::new("your-public-key", PaycheckOptions {
    storage: Some(Arc::new(storage)),
    ..Default::default()
})?;
```

## Error Handling

```rust
use paycheck_sdk::{PaycheckError, PaycheckErrorCode};

match paycheck.activate("invalid-key", None).await {
    Ok(result) => println!("Activated!"),
    Err(e) => match e.code {
        PaycheckErrorCode::InvalidLicenseKey => println!("Key not found"),
        PaycheckErrorCode::DeviceLimitReached => println!("Too many devices"),
        PaycheckErrorCode::LicenseRevoked => println!("License was revoked"),
        PaycheckErrorCode::NetworkError => println!("Network error: {}", e.message),
        _ => println!("Error: {}", e),
    }
}
```

## Ed25519 Signature Verification

The SDK uses `ed25519-dalek` for offline signature verification:

```rust
use paycheck_sdk::{verify_token, verify_and_decode_token};

// Verify a token
let is_valid = verify_token(&token, &public_key);

// Verify and decode in one step
let claims = verify_and_decode_token(&token, &public_key)?;
```

## Offline-First Design

The SDK is designed for offline-first operation:

- `validate()` verifies Ed25519 signatures locally - no network needed
- `has_feature()`, `get_tier()`, `is_expired()` work without network
- License validity is checked via `license_exp` claim, not JWT `exp`
- Tokens auto-refresh when network is available
- JWTs can be refreshed up to 10 years after issuance

## Security

**License keys are never stored.** Only the JWT token is persisted:

- License keys are long-lived secrets - storing them risks exposure
- The JWT contains everything needed for offline validation
- `get_license_info()` uses the JWT (server derives license from JTI)
- If re-activation is needed, users enter their key again

**Device ID verification** prevents token theft:

- `validate()`, `sync()`, and `import_token()` verify the JWT's `device_id` matches the current device
- A token stolen from one device cannot be used on another
- Returns `{ valid: false, reason: "Device mismatch" }` on mismatch

## License

MIT
