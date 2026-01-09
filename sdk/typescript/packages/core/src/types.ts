/**
 * Device type for license activation
 */
export type DeviceType = 'uuid' | 'machine';

/**
 * Storage adapter interface for custom storage implementations
 */
export interface StorageAdapter {
  get(key: string): string | null | Promise<string | null>;
  set(key: string, value: string): void | Promise<void>;
  remove(key: string): void | Promise<void>;
}

/**
 * Client configuration options
 */
export interface ClientConfig {
  /** Project UUID from Paycheck dashboard */
  projectId: string;
  /** Paycheck server URL (default: "https://api.paycheck.dev") */
  baseUrl?: string;
  /** Custom storage adapter (default: localStorage) */
  storage?: StorageAdapter;
  /** Auto-refresh expired tokens (default: true) */
  autoRefresh?: boolean;
  /** Override device ID (default: auto-generated) */
  deviceId?: string;
  /** Device type (default: "uuid") */
  deviceType?: DeviceType;
}

/**
 * Parameters for starting a checkout session.
 *
 * Note: Price and variant info are configured in the product settings on Paycheck,
 * so you don't need to send them here - just the product ID.
 */
export interface CheckoutParams {
  /** Product UUID - Paycheck looks up pricing from product config */
  productId: string;
  /** Payment provider (auto-detected if not specified) */
  provider?: 'stripe' | 'lemonsqueezy';
  /** Your customer identifier (flows through to license) */
  customerId?: string;
  /** Post-payment redirect URL (must be in project's allowlist) */
  redirect?: string;
}

/**
 * Result from starting a checkout session
 */
export interface CheckoutResult {
  /** URL to redirect user to */
  checkoutUrl: string;
  /** Payment session ID */
  sessionId: string;
}

/**
 * Result from parsing callback URL.
 *
 * Note: No JWT is returned from callback - the user must call activateWithCode()
 * with their device info to get a JWT. This separates purchase from activation.
 */
export interface CallbackResult {
  /** Payment status */
  status: 'success' | 'pending';
  /** Short-lived activation code (PREFIX-XXXX-XXXX-XXXX-XXXX format, 30 min TTL) */
  code?: string;
  /** Project ID (needed for activation) */
  projectId?: string;
}

/**
 * Optional device info for activation
 */
export interface DeviceInfo {
  /** Human-readable device name */
  deviceName?: string;
}

/**
 * Result from license activation
 */
export interface ActivationResult {
  /** JWT for this device */
  token: string;
  /** When license expires (null = perpetual) */
  licenseExp: number | null;
  /** When version access expires (null = all versions) */
  updatesExp: number | null;
  /** Product tier */
  tier: string;
  /** Enabled features */
  features: string[];
  /** Short-lived activation code for future activations (PREFIX-XXXX-XXXX-XXXX-XXXX format) */
  activationCode: string;
  /** When activation code expires (30 minutes from creation) */
  activationCodeExpiresAt: number;
}

/**
 * Decoded JWT claims
 */
export interface LicenseClaims {
  // Standard JWT claims
  /** Issuer ("paycheck") */
  iss: string;
  /** Subject (license_id) */
  sub: string;
  /** Audience (project domain) */
  aud: string;
  /** JWT ID (unique per device activation) */
  jti: string;
  /** Issued at (Unix timestamp) */
  iat: number;
  /** Expires (Unix timestamp, ~1 hour) */
  exp: number;

  // Paycheck claims
  /** When license access ends (null = perpetual) */
  license_exp: number | null;
  /** When version access ends (null = all versions) */
  updates_exp: number | null;
  /** Product tier */
  tier: string;
  /** Enabled features */
  features: string[];
  /** Device identifier */
  device_id: string;
  /** Device type */
  device_type: DeviceType;
  /** Product UUID */
  product_id: string;
}

/**
 * Result from online validation
 */
export interface ValidateResult {
  /** Whether the license is valid */
  valid: boolean;
  /** When license expires (if valid) */
  licenseExp?: number | null;
  /** When version access expires (if valid) */
  updatesExp?: number | null;
}

/**
 * Device info from license info endpoint
 */
export interface LicenseDeviceInfo {
  deviceId: string;
  deviceType: DeviceType;
  name: string | null;
  activatedAt: number;
  lastSeenAt: number;
}

/**
 * Full license information
 */
export interface LicenseInfo {
  /** License status */
  status: 'active' | 'expired' | 'revoked';
  /** When license was created */
  createdAt: number;
  /** When license expires (null = perpetual) */
  expiresAt: number | null;
  /** When version access expires */
  updatesExpiresAt: number | null;
  /** Number of times license has been activated */
  activationCount: number;
  /** Maximum activations allowed */
  activationLimit: number;
  /** Current number of active devices */
  deviceCount: number;
  /** Maximum devices allowed */
  deviceLimit: number;
  /** Active devices */
  devices: LicenseDeviceInfo[];
}

/**
 * Result from device deactivation
 */
export interface DeactivateResult {
  /** Whether deactivation was successful */
  deactivated: boolean;
  /** Number of remaining active devices */
  remainingDevices: number;
}

/**
 * Error codes for Paycheck errors
 */
export type PaycheckErrorCode =
  | 'NO_TOKEN'
  | 'TOKEN_EXPIRED'
  | 'LICENSE_EXPIRED'
  | 'LICENSE_REVOKED'
  | 'DEVICE_LIMIT_REACHED'
  | 'ACTIVATION_LIMIT_REACHED'
  | 'INVALID_LICENSE_KEY'
  | 'INVALID_CODE'
  | 'NETWORK_ERROR'
  | 'VALIDATION_ERROR';

/**
 * Paycheck SDK error
 */
export class PaycheckError extends Error {
  constructor(
    public code: PaycheckErrorCode,
    message: string,
    public statusCode?: number
  ) {
    super(message);
    this.name = 'PaycheckError';
  }
}
