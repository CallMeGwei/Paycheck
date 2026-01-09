import type {
  StorageAdapter,
  DeviceType,
  CheckoutParams,
  CheckoutResult,
  CallbackResult,
  DeviceInfo,
  ActivationResult,
  LicenseClaims,
  ValidateResult,
  LicenseInfo,
  DeactivateResult,
} from './types';
import { PaycheckError } from './types';
import {
  createLocalStorageAdapter,
  getOrCreateDeviceId,
  STORAGE_KEYS,
} from './storage';
import {
  decodeToken,
  verifyToken,
  verifyAndDecodeToken,
  isJwtExpired,
  isLicenseExpired,
  coversVersion as checkCoversVersion,
  hasFeature as checkHasFeature,
} from './jwt';

/**
 * Paycheck SDK configuration options
 */
export interface PaycheckOptions {
  /** Paycheck server URL (default: "https://api.paycheck.dev") */
  baseUrl?: string;
  /** Custom storage adapter (default: localStorage) */
  storage?: StorageAdapter;
  /** Device type (default: "uuid") */
  deviceType?: DeviceType;
  /** Override device ID (default: auto-generated) */
  deviceId?: string;
  /** Auto-refresh expired tokens (default: true) */
  autoRefresh?: boolean;
}

/**
 * Result from offline validation
 */
export interface OfflineValidateResult {
  /** Whether the license is valid */
  valid: boolean;
  /** Decoded claims if valid */
  claims?: LicenseClaims;
  /** Reason for invalidity */
  reason?: string;
}

/**
 * Result from sync operation
 */
export interface SyncResult {
  /** Whether the license is valid */
  valid: boolean;
  /** Decoded claims if valid */
  claims?: LicenseClaims;
  /** Whether the server was reached */
  synced: boolean;
  /** Whether operating in offline mode (using cached JWT) */
  offline: boolean;
  /** Reason for invalidity */
  reason?: string;
}

/**
 * Result from importing a token
 */
export interface ImportResult {
  /** Whether the token was valid and imported */
  valid: boolean;
  /** Decoded claims if valid */
  claims?: LicenseClaims;
  /** Reason for invalidity */
  reason?: string;
}

/** Default Paycheck API URL */
const DEFAULT_BASE_URL = 'https://api.paycheck.dev';

/**
 * Maps HTTP status codes to error codes
 */
function mapStatusToErrorCode(
  status: number,
  message: string
): PaycheckError['code'] {
  const lowerMessage = message.toLowerCase();

  if (status === 401 || status === 403) {
    if (lowerMessage.includes('revoked')) return 'LICENSE_REVOKED';
    if (lowerMessage.includes('expired')) return 'LICENSE_EXPIRED';
    if (lowerMessage.includes('device limit')) return 'DEVICE_LIMIT_REACHED';
    if (lowerMessage.includes('activation limit'))
      return 'ACTIVATION_LIMIT_REACHED';
    return 'INVALID_LICENSE_KEY';
  }

  if (status === 404) {
    if (lowerMessage.includes('code')) return 'INVALID_CODE';
    return 'INVALID_LICENSE_KEY';
  }

  if (status === 400) {
    return 'VALIDATION_ERROR';
  }

  return 'NETWORK_ERROR';
}

/**
 * Paycheck SDK client.
 *
 * Initialize with your project's public key from the Paycheck dashboard.
 * The public key enables offline JWT signature verification using Ed25519.
 *
 * @example
 * ```typescript
 * const paycheck = new Paycheck('your-base64-public-key');
 *
 * // Start a purchase
 * const { checkoutUrl } = await paycheck.checkout('product-uuid');
 *
 * // Validate license (offline, verifies Ed25519 signature)
 * const { valid, claims } = await paycheck.validate();
 * ```
 */
export class Paycheck {
  private publicKey: string;
  private baseUrl: string;
  private storage: StorageAdapter;
  private deviceId: string;
  private deviceType: DeviceType;
  private autoRefresh: boolean;

  /**
   * Creates a new Paycheck client.
   *
   * @param publicKey - Base64-encoded Ed25519 public key from your Paycheck dashboard
   * @param options - Optional configuration
   */
  constructor(publicKey: string, options: PaycheckOptions = {}) {
    if (!publicKey) {
      throw new PaycheckError('VALIDATION_ERROR', 'publicKey is required');
    }

    this.publicKey = publicKey;
    this.baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
    this.storage = options.storage ?? createLocalStorageAdapter();
    this.deviceType = options.deviceType ?? 'uuid';
    this.deviceId = options.deviceId ?? getOrCreateDeviceId(this.storage);
    this.autoRefresh = options.autoRefresh ?? true;
  }

  // ==================== Private Helpers ====================

  private getStoredToken(): string | null {
    const result = this.storage.get(STORAGE_KEYS.TOKEN);
    if (result instanceof Promise) {
      throw new PaycheckError(
        'VALIDATION_ERROR',
        'Async storage not supported for sync operations. ' +
          'Use async methods or provide sync storage.'
      );
    }
    return result;
  }

  private async storeToken(token: string): Promise<void> {
    await this.storage.set(STORAGE_KEYS.TOKEN, token);
  }

  private async apiRequest<T>(
    method: string,
    path: string,
    options: {
      body?: unknown;
      headers?: Record<string, string>;
      query?: Record<string, string>;
    } = {}
  ): Promise<T> {
    let url = `${this.baseUrl}${path}`;

    if (options.query) {
      const params = new URLSearchParams(options.query);
      url += `?${params.toString()}`;
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorObj = errorData as { error?: string; details?: string };
        const message = errorObj.details
          ? `${errorObj.error}: ${errorObj.details}`
          : errorObj.error || `Request failed: ${response.status}`;
        throw new PaycheckError(
          mapStatusToErrorCode(response.status, message),
          message,
          response.status
        );
      }

      return (await response.json()) as T;
    } catch (error) {
      if (error instanceof PaycheckError) {
        throw error;
      }
      throw new PaycheckError(
        'NETWORK_ERROR',
        error instanceof Error ? error.message : 'Network request failed'
      );
    }
  }

  private async ensureFreshToken(): Promise<string> {
    const token = this.getStoredToken();
    if (!token) {
      throw new PaycheckError('NO_TOKEN', 'No token stored');
    }

    if (this.autoRefresh) {
      try {
        const claims = decodeToken(token);
        if (isJwtExpired(claims)) {
          return await this.refreshToken();
        }
      } catch {
        // If we can't decode, try to use it anyway
      }
    }

    return token;
  }

  // ==================== Core Methods ====================

  /**
   * Start a checkout session to purchase a product.
   *
   * @param productId - Product UUID from Paycheck dashboard
   * @param options - Optional checkout parameters
   * @returns Checkout URL and session ID
   */
  async checkout(
    productId: string,
    options: Omit<CheckoutParams, 'productId'> = {}
  ): Promise<CheckoutResult> {
    const body = {
      public_key: this.publicKey,
      product_id: productId,
      provider: options.provider,
      customer_id: options.customerId,
      redirect: options.redirect,
    };

    return this.apiRequest<CheckoutResult>('POST', '/buy', { body });
  }

  /**
   * Validate the stored license.
   *
   * By default, performs offline validation by verifying the Ed25519 signature
   * and checking expiration. Use `{ online: true }` to also check revocation
   * with the server.
   *
   * @param options - Validation options
   * @returns Validation result with claims if valid
   */
  async validate(options?: {
    online?: boolean;
    token?: string;
  }): Promise<OfflineValidateResult> {
    const token = options?.token || this.getStoredToken();
    if (!token) {
      return { valid: false };
    }

    // Verify signature
    const signatureValid = await verifyToken(token, this.publicKey);
    if (!signatureValid) {
      return { valid: false, reason: 'Invalid signature' };
    }

    // Decode claims
    let claims: LicenseClaims;
    try {
      claims = decodeToken(token);
    } catch {
      return { valid: false, reason: 'Invalid token format' };
    }

    // Check device ID matches
    if (claims.device_id !== this.deviceId) {
      return { valid: false, reason: 'Device mismatch', claims };
    }

    // Check license expiration
    if (isLicenseExpired(claims)) {
      return { valid: false, reason: 'License expired', claims };
    }

    // Online validation if requested
    if (options?.online) {
      try {
        interface ValidateResponse {
          valid: boolean;
          license_exp?: number | null;
          updates_exp?: number | null;
        }

        const response = await this.apiRequest<ValidateResponse>(
          'GET',
          '/validate',
          {
            query: {
              public_key: this.publicKey,
              jti: claims.jti,
            },
          }
        );

        if (!response.valid) {
          return { valid: false, reason: 'Revoked or invalid', claims };
        }
      } catch {
        return { valid: false, reason: 'Online validation failed', claims };
      }
    }

    return { valid: true, claims };
  }

  /**
   * Sync with the server and validate the license.
   *
   * This is the recommended method for online/subscription apps. It:
   * 1. Tries to reach the server to check for updates (renewals, revocation)
   * 2. Refreshes the token if the server has newer expiration dates
   * 3. Falls back to offline validation if the server is unreachable
   *
   * Always returns a result - never throws for network failures.
   *
   * @returns Sync result with validation status
   *
   * @example
   * ```typescript
   * // On app startup for subscription apps
   * const { valid, claims, synced, offline } = await paycheck.sync();
   *
   * if (valid) {
   *   if (offline) showToast('Offline mode - using cached license');
   *   loadApp(claims.tier);
   * } else {
   *   if (!synced) {
   *     showError('Please connect to verify your license');
   *   } else {
   *     showActivationPrompt();
   *   }
   * }
   * ```
   */
  async sync(): Promise<SyncResult> {
    const token = this.getStoredToken();
    if (!token) {
      return {
        valid: false,
        synced: false,
        offline: true,
      };
    }

    // First, verify signature locally
    const signatureValid = await verifyToken(token, this.publicKey);
    if (!signatureValid) {
      return {
        valid: false,
        synced: false,
        offline: true,
        reason: 'Invalid signature',
      };
    }

    // Decode claims
    let claims: LicenseClaims;
    try {
      claims = decodeToken(token);
    } catch {
      return {
        valid: false,
        synced: false,
        offline: true,
        reason: 'Invalid token format',
      };
    }

    // Check device ID matches
    if (claims.device_id !== this.deviceId) {
      return {
        valid: false,
        synced: false,
        offline: true,
        reason: 'Device mismatch',
      };
    }

    // Try to sync with server
    try {
      interface ValidateResponse {
        valid: boolean;
        license_exp?: number | null;
        updates_exp?: number | null;
      }

      const response = await this.apiRequest<ValidateResponse>(
        'GET',
        '/validate',
        {
          query: {
            public_key: this.publicKey,
            jti: claims.jti,
          },
        }
      );

      if (!response.valid) {
        return {
          valid: false,
          synced: true,
          offline: false,
          reason: 'Revoked or invalid',
          claims,
        };
      }

      // Check if server has updated expiration - refresh token if so
      const serverLicenseExp = response.license_exp ?? null;
      const localLicenseExp = claims.license_exp ?? null;

      if (serverLicenseExp !== localLicenseExp) {
        try {
          await this.refreshToken();
          // Re-decode after refresh
          const newToken = this.getStoredToken();
          if (newToken) {
            claims = decodeToken(newToken);
          }
        } catch {
          // Refresh failed, but validation passed - continue with current token
        }
      }

      // Check license expiration with potentially updated claims
      if (isLicenseExpired(claims)) {
        return {
          valid: false,
          synced: true,
          offline: false,
          reason: 'License expired',
          claims,
        };
      }

      return {
        valid: true,
        synced: true,
        offline: false,
        claims,
      };
    } catch {
      // Server unreachable - fall back to offline validation
      if (isLicenseExpired(claims)) {
        return {
          valid: false,
          synced: false,
          offline: true,
          reason: 'License expired',
          claims,
        };
      }

      return {
        valid: true,
        synced: false,
        offline: true,
        claims,
      };
    }
  }

  /**
   * Activate using an activation code.
   *
   * Activation codes are short-lived (30 min TTL) and in PREFIX-XXXX-XXXX-XXXX-XXXX format.
   * They're returned from:
   * - Payment callback URL (after successful purchase)
   * - Email recovery flow (POST /activation/request-code)
   * - Admin API (POST /orgs/.../licenses/{id}/send-code)
   *
   * @param code - Activation code (PREFIX-XXXX-XXXX-XXXX-XXXX format)
   * @param options - Optional device info
   * @returns Activation result with token
   */
  async activateWithCode(
    code: string,
    options?: DeviceInfo
  ): Promise<ActivationResult> {
    interface RedeemResponse {
      token: string;
      license_exp: number | null;
      updates_exp: number | null;
      tier: string;
      features: string[];
      activation_code: string;
      activation_code_expires_at: number;
    }

    const response = await this.apiRequest<RedeemResponse>('GET', '/redeem', {
      query: {
        public_key: this.publicKey,
        code,
        device_id: this.deviceId,
        device_type: this.deviceType,
        ...(options?.deviceName && { device_name: options.deviceName }),
      },
    });

    await this.storeToken(response.token);

    return {
      token: response.token,
      licenseExp: response.license_exp,
      updatesExp: response.updates_exp,
      tier: response.tier,
      features: response.features,
      activationCode: response.activation_code,
      activationCodeExpiresAt: response.activation_code_expires_at,
    };
  }

  /**
   * Import a JWT token directly (offline activation).
   *
   * Use this when you have a JWT from another source (clipboard, QR code,
   * file, enterprise IT distribution). The token is verified locally using
   * Ed25519 signature verification - no network required.
   *
   * @param token - JWT token to import
   * @returns Import result with claims if valid
   *
   * @example
   * ```typescript
   * // Offline activation from clipboard
   * const jwt = await navigator.clipboard.readText();
   * const { valid, claims } = await paycheck.importToken(jwt);
   * if (valid) {
   *   console.log('Activated offline! Tier:', claims.tier);
   * }
   * ```
   */
  async importToken(token: string): Promise<ImportResult> {
    // Verify Ed25519 signature
    const signatureValid = await verifyToken(token, this.publicKey);
    if (!signatureValid) {
      return { valid: false, reason: 'Invalid signature' };
    }

    // Decode and validate claims
    let claims: LicenseClaims;
    try {
      claims = decodeToken(token);
    } catch {
      return { valid: false, reason: 'Invalid token format' };
    }

    // Check device ID matches
    if (claims.device_id !== this.deviceId) {
      return { valid: false, reason: 'Device mismatch', claims };
    }

    // Check license expiration
    if (isLicenseExpired(claims)) {
      return { valid: false, reason: 'License expired', claims };
    }

    // Valid - store the token
    await this.storeToken(token);

    return { valid: true, claims };
  }

  // ==================== Helper Methods ====================

  /**
   * Quick check if a valid license is stored.
   * Performs offline signature verification.
   */
  async isLicensed(): Promise<boolean> {
    const result = await this.validate();
    return result.valid;
  }

  /**
   * Get decoded license claims (without signature verification).
   * Use validate() for secure verification.
   */
  getLicense(): LicenseClaims | null {
    const token = this.getStoredToken();
    if (!token) return null;

    try {
      return decodeToken(token);
    } catch {
      return null;
    }
  }

  /**
   * Check if license has a specific feature.
   */
  hasFeature(feature: string): boolean {
    const claims = this.getLicense();
    if (!claims) return false;
    return checkHasFeature(claims, feature);
  }

  /**
   * Get the product tier.
   */
  getTier(): string | null {
    const claims = this.getLicense();
    return claims?.tier ?? null;
  }

  /**
   * Check if the license is expired.
   */
  isExpired(): boolean {
    const claims = this.getLicense();
    if (!claims) return true;
    return isLicenseExpired(claims);
  }

  /**
   * Check if the license covers a specific version by its release timestamp.
   */
  coversVersion(timestamp: number): boolean {
    const claims = this.getLicense();
    if (!claims) return false;
    return checkCoversVersion(claims, timestamp);
  }

  // ==================== Token Management ====================

  /**
   * Get the stored JWT token.
   */
  getToken(): string | null {
    return this.getStoredToken();
  }

  /**
   * Clear stored token.
   */
  clearToken(): void {
    this.storage.remove(STORAGE_KEYS.TOKEN);
  }

  /**
   * Refresh the JWT token.
   */
  async refreshToken(): Promise<string> {
    const token = this.getStoredToken();
    if (!token) {
      throw new PaycheckError('NO_TOKEN', 'No token to refresh');
    }

    interface RefreshResponse {
      token: string;
    }

    const response = await this.apiRequest<RefreshResponse>('POST', '/refresh', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await this.storeToken(response.token);
    return response.token;
  }

  // ==================== Device Management ====================

  /**
   * Deactivate this device.
   */
  async deactivate(): Promise<DeactivateResult> {
    const token = await this.ensureFreshToken();

    interface DeactivateResponse {
      deactivated: boolean;
      remaining_devices: number;
    }

    const response = await this.apiRequest<DeactivateResponse>(
      'POST',
      '/devices/deactivate',
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    this.clearToken();

    return {
      deactivated: response.deactivated,
      remainingDevices: response.remaining_devices,
    };
  }

  /**
   * Get full license information including devices.
   * Uses the stored JWT token for authentication.
   */
  async getLicenseInfo(): Promise<LicenseInfo> {
    const token = await this.ensureFreshToken();

    interface LicenseResponse {
      status: 'active' | 'expired' | 'revoked';
      created_at: number;
      expires_at: number | null;
      updates_expires_at: number | null;
      activation_count: number;
      activation_limit: number;
      device_count: number;
      device_limit: number;
      devices: Array<{
        device_id: string;
        device_type: 'uuid' | 'machine';
        name: string | null;
        activated_at: number;
        last_seen_at: number;
      }>;
    }

    const response = await this.apiRequest<LicenseResponse>('GET', '/license', {
      query: {
        public_key: this.publicKey,
      },
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    return {
      status: response.status,
      createdAt: response.created_at,
      expiresAt: response.expires_at,
      updatesExpiresAt: response.updates_expires_at,
      activationCount: response.activation_count,
      activationLimit: response.activation_limit,
      deviceCount: response.device_count,
      deviceLimit: response.device_limit,
      devices: response.devices.map((d) => ({
        deviceId: d.device_id,
        deviceType: d.device_type,
        name: d.name,
        activatedAt: d.activated_at,
        lastSeenAt: d.last_seen_at,
      })),
    };
  }

  // ==================== Callback Handling ====================

  /**
   * Handle the callback URL after payment redirect.
   * Returns the activation code for device activation.
   *
   * The activation code is short-lived (30 min) and should be passed to
   * activateWithCode() to complete activation on this device.
   */
  handleCallback(url: string): CallbackResult {
    const urlObj = new URL(url);
    const params = urlObj.searchParams;

    const status = (params.get('status') || 'success') as 'success' | 'pending';
    const code = params.get('code') || undefined;
    const projectId = params.get('project_id') || undefined;

    return { status, code, projectId };
  }
}

/**
 * Creates a new Paycheck client.
 *
 * @param publicKey - Base64-encoded Ed25519 public key
 * @param options - Optional configuration
 */
export function createPaycheck(
  publicKey: string,
  options?: PaycheckOptions
): Paycheck {
  return new Paycheck(publicKey, options);
}
