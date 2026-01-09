# Paycheck SDK Implementation Plan

## Overview

Create developer-friendly SDKs for Paycheck that let developers integrate licensing in minutes. Start with TypeScript (for web/Next.js) and Rust (for native desktop apps).

## Folder Structure

```
sdk/
├── CORE.md                    # Language-agnostic function specs
├── typescript/
│   ├── packages/
│   │   ├── core/              # @paycheck/sdk - vanilla JS/TS
│   │   │   ├── package.json
│   │   │   ├── tsconfig.json
│   │   │   └── src/
│   │   │       ├── index.ts
│   │   │       ├── client.ts
│   │   │       ├── types.ts
│   │   │       ├── storage.ts
│   │   │       └── jwt.ts
│   │   └── react/             # @paycheck/react - React hooks
│   │       ├── package.json
│   │       ├── tsconfig.json
│   │       └── src/
│   │           ├── index.ts
│   │           ├── provider.tsx
│   │           └── hooks.ts
│   └── README.md
└── rust/
    ├── Cargo.toml             # paycheck-sdk crate
    ├── src/
    │   ├── lib.rs
    │   ├── client.rs
    │   ├── types.rs
    │   ├── storage.rs
    │   ├── jwt.rs
    │   └── device.rs          # Hardware ID generation
    └── README.md
```

## CORE.md - Function Specifications

Every SDK must implement these functions with consistent naming:

### Configuration

```
createClient(config: ClientConfig) -> Client

ClientConfig:
  - baseUrl: string           # Paycheck server URL
  - projectId: string         # Project UUID
  - storage?: StorageAdapter  # Custom storage (default: localStorage/file)
  - autoRefresh?: boolean     # Auto-refresh tokens (default: true)
  - deviceId?: string         # Override device ID (default: auto-generated)
  - deviceType?: "uuid"|"machine"  # Default: "uuid" for web, "machine" for desktop
```

### Payment Flow

```
startCheckout(params) -> { checkoutUrl, sessionId }

params:
  - productId: string
  - priceCents?: number       # Required for Stripe
  - variantId?: string        # Required for LemonSqueezy
  - customerId?: string       # Your customer identifier
  - redirect?: string         # Post-payment redirect URL

handleCallback(url: string) -> { token, licenseKey?, code?, status }
  - Parses callback URL params
  - Stores token automatically
  - Returns extracted credentials
```

### License Activation

```
activate(licenseKey: string, deviceInfo?) -> ActivationResult
  - Exchanges license key for JWT
  - Stores token automatically
  - Returns: { token, licenseExp, updatesExp, tier, features, code }

activateWithCode(code: string, deviceInfo?) -> ActivationResult
  - Same as activate() but uses redemption code
```

### Token Operations

```
getToken() -> string | null
  - Returns stored JWT (or null if none)

refreshToken() -> string
  - Refreshes current token (works even if expired)
  - Updates stored token
  - Throws if no token or refresh fails

clearToken() -> void
  - Removes stored token and license data
```

### License Checking (Offline)

```
isLicensed() -> boolean
  - Returns true if valid token exists and license not expired
  - Does NOT make network calls

getLicense() -> LicenseClaims | null
  - Returns decoded JWT claims (or null)
  - Does NOT make network calls

hasFeature(feature: string) -> boolean
  - Checks if feature is in license's features array

getTier() -> string | null
  - Returns current tier from license

isExpired() -> boolean
  - Checks if license_exp has passed

coversVersion(timestamp: number) -> boolean
  - Checks if updates_exp covers the given version timestamp
```

### Online Operations

```
validate() -> { valid, licenseExp?, updatesExp? }
  - Online validation (checks revocation)
  - Updates last_seen on server

getLicenseInfo() -> LicenseInfo
  - Returns full license info including devices, counts

deactivate() -> { deactivated, remainingDevices }
  - Self-deactivates current device
  - Clears stored token
```

### Types

```typescript
// Response from activate/activateWithCode
interface ActivationResult {
  token: string;
  licenseExp: number | null;
  updatesExp: number | null;
  tier: string;
  features: string[];
  redemptionCode: string;
  redemptionCodeExpiresAt: number;
}

// Decoded JWT claims
interface LicenseClaims {
  // Standard JWT
  iss: string;        // "paycheck"
  sub: string;        // license_id
  aud: string;        // project domain
  jti: string;        // unique token ID
  iat: number;
  exp: number;

  // Paycheck claims
  license_exp: number | null;
  updates_exp: number | null;
  tier: string;
  features: string[];
  device_id: string;
  device_type: "uuid" | "machine";
  product_id: string;
}

// Response from getLicenseInfo()
interface LicenseInfo {
  status: "active" | "expired" | "revoked";
  createdAt: number;
  expiresAt: number | null;
  updatesExpiresAt: number | null;
  activationCount: number;
  activationLimit: number;
  deviceCount: number;
  deviceLimit: number;
  devices: DeviceInfo[];
}

interface DeviceInfo {
  deviceId: string;
  deviceType: "uuid" | "machine";
  name: string | null;
  activatedAt: number;
  lastSeenAt: number;
}

// Storage adapter interface
interface StorageAdapter {
  get(key: string): string | null | Promise<string | null>;
  set(key: string, value: string): void | Promise<void>;
  remove(key: string): void | Promise<void>;
}
```

## TypeScript SDK Implementation

### @paycheck/sdk (Core)

**src/index.ts** - Main exports:
```typescript
export { createClient } from './client';
export type { PaycheckClient, ClientConfig, StorageAdapter } from './client';
export type { LicenseClaims, ActivationResult, LicenseInfo } from './types';
```

**src/client.ts** - Client implementation:
```typescript
export interface ClientConfig {
  baseUrl: string;
  projectId: string;
  storage?: StorageAdapter;
  autoRefresh?: boolean;
  deviceId?: string;
  deviceType?: 'uuid' | 'machine';
}

export function createClient(config: ClientConfig): PaycheckClient {
  const storage = config.storage ?? createLocalStorageAdapter();
  const deviceId = config.deviceId ?? getOrCreateDeviceId(storage);
  const deviceType = config.deviceType ?? 'uuid';

  return {
    // Payment flow
    async startCheckout(params) { ... },
    handleCallback(url) { ... },

    // Activation
    async activate(licenseKey, deviceInfo?) { ... },
    async activateWithCode(code, deviceInfo?) { ... },

    // Token operations
    getToken() { ... },
    async refreshToken() { ... },
    clearToken() { ... },

    // Offline checks
    isLicensed() { ... },
    getLicense() { ... },
    hasFeature(feature) { ... },
    getTier() { ... },
    isExpired() { ... },
    coversVersion(timestamp) { ... },

    // Online operations
    async validate() { ... },
    async getLicenseInfo() { ... },
    async deactivate() { ... },
  };
}
```

**src/storage.ts** - Storage adapters:
```typescript
export interface StorageAdapter {
  get(key: string): string | null | Promise<string | null>;
  set(key: string, value: string): void | Promise<void>;
  remove(key: string): void | Promise<void>;
}

// Default: localStorage
export function createLocalStorageAdapter(): StorageAdapter { ... }

// Memory storage (for SSR/testing)
export function createMemoryStorage(): StorageAdapter { ... }
```

**src/jwt.ts** - JWT decoding (no verification needed client-side):
```typescript
export function decodeToken(token: string): LicenseClaims { ... }
export function isTokenExpired(claims: LicenseClaims): boolean { ... }
```

### @paycheck/react (React Hooks)

**src/provider.tsx**:
```typescript
import { createContext, useContext, useState, useEffect } from 'react';
import { createClient, PaycheckClient, ClientConfig } from '@paycheck/sdk';

const PaycheckContext = createContext<PaycheckClient | null>(null);

export function PaycheckProvider({
  children,
  config
}: {
  children: React.ReactNode;
  config: ClientConfig;
}) {
  const [client] = useState(() => createClient(config));

  return (
    <PaycheckContext.Provider value={client}>
      {children}
    </PaycheckContext.Provider>
  );
}

export function usePaycheckClient(): PaycheckClient {
  const client = useContext(PaycheckContext);
  if (!client) throw new Error('Must be used within PaycheckProvider');
  return client;
}
```

**src/hooks.ts**:
```typescript
// Main hook - returns license state and methods
export function useLicense() {
  const client = usePaycheckClient();
  const [license, setLicense] = useState<LicenseClaims | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLicense(client.getLicense());
    setLoading(false);
  }, [client]);

  return {
    license,
    loading,
    isLicensed: client.isLicensed(),
    tier: client.getTier(),
    features: license?.features ?? [],

    // Methods
    activate: client.activate.bind(client),
    activateWithCode: client.activateWithCode.bind(client),
    refresh: client.refreshToken.bind(client),
    deactivate: client.deactivate.bind(client),
  };
}

// Simple boolean check
export function useLicenseStatus() {
  const client = usePaycheckClient();
  return {
    isLicensed: client.isLicensed(),
    isExpired: client.isExpired(),
    tier: client.getTier(),
  };
}

// Feature flag check
export function useFeature(feature: string): boolean {
  const client = usePaycheckClient();
  return client.hasFeature(feature);
}

// Version gating
export function useVersionAccess(versionTimestamp: number): boolean {
  const client = usePaycheckClient();
  return client.coversVersion(versionTimestamp);
}
```

### Usage Example (Next.js)

```tsx
// app/providers.tsx
'use client';
import { PaycheckProvider } from '@paycheck/react';

export function Providers({ children }) {
  return (
    <PaycheckProvider config={{
      baseUrl: process.env.NEXT_PUBLIC_PAYCHECK_URL!,
      projectId: process.env.NEXT_PUBLIC_PAYCHECK_PROJECT_ID!,
    }}>
      {children}
    </PaycheckProvider>
  );
}

// app/pricing/page.tsx
'use client';
import { usePaycheckClient } from '@paycheck/react';

export default function PricingPage() {
  const client = usePaycheckClient();

  async function handleBuy() {
    const { checkoutUrl } = await client.startCheckout({
      productId: 'pro-tier-uuid',
      priceCents: 2999,
    });
    window.location.href = checkoutUrl;
  }

  return <button onClick={handleBuy}>Buy Pro - $29.99</button>;
}

// app/callback/page.tsx
'use client';
import { usePaycheckClient } from '@paycheck/react';
import { useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

export default function CallbackPage() {
  const client = usePaycheckClient();
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const result = client.handleCallback(window.location.href);
    if (result.status === 'success') {
      router.push('/dashboard');
    }
  }, []);

  return <div>Processing payment...</div>;
}

// components/pro-feature.tsx
'use client';
import { useFeature, useLicense } from '@paycheck/react';

export function ProFeature({ children }) {
  const hasAccess = useFeature('pro');
  const { activate } = useLicense();

  if (!hasAccess) {
    return (
      <div>
        <p>This feature requires Pro</p>
        <input
          placeholder="Enter license key"
          onKeyDown={async (e) => {
            if (e.key === 'Enter') {
              await activate(e.currentTarget.value);
            }
          }}
        />
      </div>
    );
  }

  return children;
}
```

## Rust SDK Implementation

### Crate: paycheck-sdk

**Cargo.toml**:
```toml
[package]
name = "paycheck-sdk"
version = "0.1.0"
edition = "2024"

[features]
default = ["native-storage"]
native-storage = ["directories"]

[dependencies]
reqwest = { version = "0.12", features = ["json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
thiserror = "2"
directories = { version = "5", optional = true }
uuid = { version = "1", features = ["v4"] }

# For hardware ID on desktop
[target.'cfg(target_os = "macos")'.dependencies]
# macOS: IOKit for hardware IDs

[target.'cfg(target_os = "linux")'.dependencies]
# Linux: /etc/machine-id

[target.'cfg(target_os = "windows")'.dependencies]
# Windows: registry for MachineGuid
```

**src/lib.rs**:
```rust
pub mod client;
pub mod types;
pub mod storage;
pub mod jwt;
pub mod device;
pub mod error;

pub use client::{PaycheckClient, ClientConfig};
pub use types::*;
pub use storage::StorageAdapter;
pub use error::PaycheckError;
```

**src/client.rs**:
```rust
pub struct ClientConfig {
    pub base_url: String,
    pub project_id: String,
    pub storage: Option<Box<dyn StorageAdapter>>,
    pub auto_refresh: bool,
    pub device_id: Option<String>,
    pub device_type: DeviceType,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            project_id: String::new(),
            storage: None,
            auto_refresh: true,
            device_id: None,
            device_type: DeviceType::Machine, // Desktop default
        }
    }
}

pub struct PaycheckClient { ... }

impl PaycheckClient {
    pub fn new(config: ClientConfig) -> Self { ... }

    // Payment flow
    pub async fn start_checkout(&self, params: CheckoutParams) -> Result<CheckoutResult>;
    pub fn handle_callback(&self, url: &str) -> Result<CallbackResult>;

    // Activation
    pub async fn activate(&self, license_key: &str) -> Result<ActivationResult>;
    pub async fn activate_with_code(&self, code: &str) -> Result<ActivationResult>;

    // Token operations
    pub fn get_token(&self) -> Option<String>;
    pub async fn refresh_token(&self) -> Result<String>;
    pub fn clear_token(&self);

    // Offline checks
    pub fn is_licensed(&self) -> bool;
    pub fn get_license(&self) -> Option<LicenseClaims>;
    pub fn has_feature(&self, feature: &str) -> bool;
    pub fn get_tier(&self) -> Option<String>;
    pub fn is_expired(&self) -> bool;
    pub fn covers_version(&self, timestamp: i64) -> bool;

    // Online operations
    pub async fn validate(&self) -> Result<ValidateResult>;
    pub async fn get_license_info(&self) -> Result<LicenseInfo>;
    pub async fn deactivate(&self) -> Result<DeactivateResult>;
}
```

**src/device.rs** - Hardware ID generation:
```rust
/// Generate a stable machine ID for desktop apps
///
/// Platform-specific:
/// - macOS: IOPlatformSerialNumber from IOKit
/// - Linux: /etc/machine-id
/// - Windows: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
pub fn get_machine_id() -> Result<String> { ... }

/// Generate a random UUID (for apps that don't need hardware binding)
pub fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}
```

**src/storage.rs**:
```rust
pub trait StorageAdapter: Send + Sync {
    fn get(&self, key: &str) -> Option<String>;
    fn set(&self, key: &str, value: &str);
    fn remove(&self, key: &str);
}

/// Default file-based storage in app data directory
#[cfg(feature = "native-storage")]
pub struct FileStorage { ... }

/// In-memory storage for testing
pub struct MemoryStorage { ... }
```

### Rust Usage Example

```rust
use paycheck_sdk::{PaycheckClient, ClientConfig, DeviceType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = PaycheckClient::new(ClientConfig {
        base_url: "https://pay.myapp.com".into(),
        project_id: "project-uuid".into(),
        device_type: DeviceType::Machine,
        ..Default::default()
    });

    // Check if already licensed
    if client.is_licensed() {
        println!("Licensed! Tier: {:?}", client.get_tier());
        return Ok(());
    }

    // Activate with license key
    let result = client.activate("PC-XXXXX").await?;
    println!("Activated! Tier: {}", result.tier);

    // Feature gating
    if client.has_feature("export") {
        // Enable export functionality
    }

    Ok(())
}
```

## Implementation Order

1. **Create folder structure and CORE.md** - Define the contract all SDKs follow
2. **TypeScript core package** - `@paycheck/sdk` with all core functions
3. **TypeScript React package** - `@paycheck/react` with hooks
4. **Test with Next.js app** - Verify the DX is smooth
5. **Rust SDK** - Mirror the TypeScript implementation
6. **Documentation** - README files with examples

## Files to Create

| Path | Description |
|------|-------------|
| `sdk/CORE.md` | Language-agnostic function specifications |
| `sdk/typescript/packages/core/package.json` | Core package config |
| `sdk/typescript/packages/core/tsconfig.json` | TypeScript config |
| `sdk/typescript/packages/core/src/index.ts` | Main exports |
| `sdk/typescript/packages/core/src/client.ts` | Client implementation |
| `sdk/typescript/packages/core/src/types.ts` | Type definitions |
| `sdk/typescript/packages/core/src/storage.ts` | Storage adapters |
| `sdk/typescript/packages/core/src/jwt.ts` | JWT decoding |
| `sdk/typescript/packages/react/package.json` | React package config |
| `sdk/typescript/packages/react/tsconfig.json` | TypeScript config |
| `sdk/typescript/packages/react/src/index.ts` | Main exports |
| `sdk/typescript/packages/react/src/provider.tsx` | React context provider |
| `sdk/typescript/packages/react/src/hooks.ts` | React hooks |
| `sdk/typescript/README.md` | TypeScript SDK docs |
| `sdk/rust/Cargo.toml` | Rust crate config |
| `sdk/rust/src/lib.rs` | Library root |
| `sdk/rust/src/client.rs` | Client implementation |
| `sdk/rust/src/types.rs` | Type definitions |
| `sdk/rust/src/storage.rs` | Storage trait + implementations |
| `sdk/rust/src/jwt.rs` | JWT decoding |
| `sdk/rust/src/device.rs` | Hardware ID generation |
| `sdk/rust/src/error.rs` | Error types |
| `sdk/rust/README.md` | Rust SDK docs |
