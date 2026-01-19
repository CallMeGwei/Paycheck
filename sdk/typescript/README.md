# Paycheck TypeScript SDK

Official TypeScript/JavaScript SDK for [Paycheck](https://paycheck.dev) - offline-first licensing system for vibe coders and indie devs.

## Packages

- **`@paycheck/sdk`** - Core SDK with Ed25519 signature verification
- **`@paycheck/react`** - React hooks and components

## Installation

```bash
# Core SDK only
npm install @paycheck/sdk

# With React integration
npm install @paycheck/sdk @paycheck/react
```

## Quick Start

### Vanilla JavaScript/TypeScript

```typescript
import { Paycheck } from '@paycheck/sdk';

// Initialize with your project's public key from the Paycheck dashboard
const paycheck = new Paycheck('your-base64-public-key');

// Or with options
const paycheck = new Paycheck('your-base64-public-key', {
  baseUrl: 'https://pay.myapp.com', // Optional, defaults to https://api.paycheck.dev
});

// Validate license (verifies Ed25519 signature offline!)
const { valid, claims } = await paycheck.validate();
if (valid) {
  console.log('Licensed! Tier:', claims.tier);
} else {
  // Activate with code (from payment callback or email recovery)
  const result = await paycheck.activateWithCode('MYAPP-AB3D-EF5G');
  console.log('Activated! Features:', result.features);
}

// Feature gating
if (paycheck.hasFeature('export')) {
  // Enable export functionality
}
```

### React / Next.js

```tsx
// app/providers.tsx
'use client';
import { PaycheckProvider } from '@paycheck/react';

export function Providers({ children }) {
  return (
    <PaycheckProvider publicKey={process.env.NEXT_PUBLIC_PAYCHECK_PUBLIC_KEY!}>
      {children}
    </PaycheckProvider>
  );
}

// components/app.tsx
'use client';
import { useLicense, FeatureGate, LicenseGate } from '@paycheck/react';

export function App() {
  const { isLicensed, tier, loading, activateWithCode } = useLicense();

  if (loading) return <div>Loading...</div>;

  if (!isLicensed) {
    return <ActivationCodeInput onActivate={activateWithCode} />;
  }

  return (
    <div>
      <p>Welcome! Your tier: {tier}</p>
      <FeatureGate feature="export" fallback={<UpgradePrompt />}>
        <ExportButton />
      </FeatureGate>
    </div>
  );
}

// Or use gate components for cleaner code
export function AppWithGates() {
  return (
    <LicenseGate
      fallback={<PurchasePage />}
      loading={<Spinner />}
    >
      <Dashboard />
    </LicenseGate>
  );
}
```

## Payment Flow

**Important:** The redirect URL after payment is configured per-project in your Paycheck dashboard or via the admin API, not per-request. This prevents open redirect vulnerabilities.

```typescript
// 1. Start checkout (redirect URL is configured on your project, not here)
const { checkoutUrl } = await paycheck.checkout('product-uuid');

// 2. Redirect to payment provider (Stripe/LemonSqueezy)
window.location.href = checkoutUrl;

// 3. Handle callback (on your configured redirect page, e.g., /success)
// Option A: One-step activation (recommended)
const result = await paycheck.handleCallbackAndActivate(window.location.href);
if (result.activated) {
  console.log('Welcome!', result.claims?.tier);
  window.history.replaceState({}, '', '/dashboard'); // Clean URL
} else if (result.wasCallback && result.error) {
  console.error('Activation failed:', result.error);
}

// Option B: Manual two-step flow
const callback = paycheck.handleCallback(window.location.href);
if (callback.status === 'success' && callback.code) {
  const activation = await paycheck.activateWithCode(callback.code);
  console.log('Activated! Tier:', activation.tier);
}
```

## API Reference

### Paycheck Constructor

```typescript
const paycheck = new Paycheck(publicKey: string, options?: PaycheckOptions);

interface PaycheckOptions {
  baseUrl?: string;           // Paycheck server URL (default: "https://api.paycheck.dev")
  storage?: StorageAdapter;   // Custom storage (default: localStorage)
  autoRefresh?: boolean;      // Auto-refresh tokens (default: true)
  deviceId?: string;          // Override device ID
  deviceType?: 'uuid' | 'machine'; // Default: "uuid"
}
```

### Core Methods

#### Payment Flow

- `checkout(productId, options?)` - Start a payment checkout session
- `handleCallback(url)` - Parse callback URL and extract activation code
- `handleCallbackAndActivate(url, deviceInfo?)` - Parse callback and activate in one step (recommended)

#### Activation

- `activateWithCode(code, deviceInfo?)` - Activate with activation code (PREFIX-XXXX-XXXX format)
- `requestActivationCode(email)` - Request activation code sent to purchase email
- `importToken(token)` - Import JWT directly (offline activation)

#### Validation (with Ed25519 signature verification)

- `validate(options?)` - Validate license offline with signature verification
- `sync()` - Sync with server + validate (for subscription apps)
- `isLicensed()` - Check if licensed (async, verifies signature)

#### Token Operations

- `getToken()` - Get stored JWT
- `refreshToken()` - Refresh expired token
- `clearToken()` - Clear stored credentials

#### Quick License Queries

- `getLicense()` - Get decoded claims
- `hasFeature(name)` - Check feature access
- `getTier()` - Get current tier
- `isExpired()` - Check if license expired
- `coversVersion(timestamp)` - Check version access

#### Online Operations

- `sync()` - Sync with server, refresh if needed, fallback to offline
- `getLicenseInfo()` - Get full license details with devices
- `deactivate()` - Self-deactivate device

### React Hooks

#### `useLicense(options?)`

Main hook for license state and actions. Performs Ed25519 signature verification.

```typescript
// Offline-first (default)
const { isLicensed, tier, activateWithCode } = useLicense();

// Online/subscription apps - use sync() instead of validate()
const { isLicensed, synced, offline, tier } = useLicense({ sync: true });

// Full return type
const {
  license,      // Decoded claims
  loading,      // Loading state
  isLicensed,   // Signature-verified boolean check
  tier,         // Current tier
  features,     // Feature list
  isExpired,    // Expiration check
  error,        // Error message if validation failed
  synced,       // Whether server was reached (sync mode only)
  offline,      // Whether in offline mode (sync mode only)
  activateWithCode, // Activate with code (PREFIX-XXXX-XXXX format)
  requestActivationCode, // Request code sent to purchase email
  importToken,  // Import JWT directly (offline activation)
  refresh,      // Refresh token
  deactivate,   // Deactivate device
  clear,        // Clear credentials
  reload,       // Reload from storage
} = useLicense();
```

**Cross-tab sync:** The hook automatically detects when a license is activated in another browser tab (e.g., user clicks an activation link that opens in a new tab) and updates the license state.

#### `useLicenseStatus()`

Simple status check (lighter than `useLicense`).

```typescript
const { isLicensed, isExpired, tier, loading } = useLicenseStatus();
```

#### `useFeature(name)`

Check if a feature is enabled.

```typescript
const hasExport = useFeature('export');
```

#### `useVersionAccess(timestamp)`

Check if a version is covered.

```typescript
const hasAccess = useVersionAccess(1704067200);
```

### React Components

#### `<LicenseGate>`

Gate content behind a valid license.

```tsx
<LicenseGate
  fallback={<PurchasePage />}
  loading={<Spinner />}
>
  <App />
</LicenseGate>
```

#### `<FeatureGate>`

Gate content behind a feature.

```tsx
<FeatureGate feature="export" fallback={<UpgradePrompt />}>
  <ExportButton />
</FeatureGate>
```

## Custom Storage

```typescript
import { Paycheck, type StorageAdapter } from '@paycheck/sdk';

// Example: AsyncStorage for React Native
const asyncStorageAdapter: StorageAdapter = {
  get: (key) => AsyncStorage.getItem(key),
  set: (key, value) => AsyncStorage.setItem(key, value),
  remove: (key) => AsyncStorage.removeItem(key),
};

const paycheck = new Paycheck('your-public-key', {
  storage: asyncStorageAdapter,
});
```

## Error Handling

```typescript
import { PaycheckError } from '@paycheck/sdk';

try {
  await paycheck.activateWithCode('INVALID-CODE');
} catch (error) {
  if (error instanceof PaycheckError) {
    switch (error.code) {
      case 'INVALID_CODE':
        console.log('Invalid or expired activation code');
        break;
      case 'DEVICE_LIMIT_REACHED':
        console.log('Too many devices');
        break;
      case 'LICENSE_REVOKED':
        console.log('License was revoked');
        break;
    }
  }
}
```

## Ed25519 Signature Verification

The SDK uses `@noble/ed25519` for offline signature verification:

```typescript
import { verifyToken, verifyAndDecodeToken } from '@paycheck/sdk';

// Verify a token
const isValid = await verifyToken(token, publicKey);

// Verify and decode in one step
const claims = await verifyAndDecodeToken(token, publicKey);
```

## Offline-First Design

The SDK is designed for offline-first operation:

- `validate()` verifies Ed25519 signatures locally - no network needed
- `hasFeature()`, `getTier()`, `isExpired()` work without network
- License validity is checked via `license_exp` claim, not JWT `exp`
- Tokens auto-refresh when network is available
- JWTs can be refreshed up to 10 years after issuance

## License

MIT
