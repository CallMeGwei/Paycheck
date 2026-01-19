'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import type {
  LicenseClaims,
  ActivationResult,
  DeactivateResult,
  DeviceInfo,
  ImportResult,
  CallbackActivationResult,
  RequestCodeResult,
} from '@paycheck/sdk';
import { usePaycheck } from './provider';

/**
 * Options for useLicense hook
 */
export interface UseLicenseOptions {
  /** Use sync() instead of validate() for online apps (default: false) */
  sync?: boolean;
}

/**
 * Return type for useLicense hook
 */
export interface UseLicenseResult {
  /** Decoded license claims (null if no license) */
  license: LicenseClaims | null;
  /** Loading state (true on initial load and during async operations) */
  loading: boolean;
  /** Whether there's a valid, non-expired license (with Ed25519 signature verification) */
  isLicensed: boolean;
  /** Current tier (null if no license) */
  tier: string | null;
  /** Enabled features */
  features: string[];
  /** Whether the license has expired */
  isExpired: boolean;
  /** Error message if validation failed */
  error: string | null;
  /** Whether the server was reached (only when sync: true) */
  synced: boolean;
  /** Whether operating in offline mode (only when sync: true) */
  offline: boolean;

  // Actions
  /** Activate with activation code */
  activateWithCode: (
    code: string,
    deviceInfo?: DeviceInfo
  ) => Promise<ActivationResult>;
  /** Import a JWT token directly (offline activation) */
  importToken: (token: string) => Promise<ImportResult>;
  /** Request activation code to be sent to purchase email (via webhook, org's Resend, or Paycheck.dev) */
  requestActivationCode: (email: string) => Promise<RequestCodeResult>;
  /** Refresh the token */
  refresh: () => Promise<string>;
  /** Deactivate current device */
  deactivate: () => Promise<DeactivateResult>;
  /** Clear stored license */
  clear: () => void;
  /** Reload/revalidate license from storage */
  reload: () => void;
}

/**
 * Main hook for license state and actions.
 * Performs Ed25519 signature verification for secure offline validation.
 *
 * @param options - Hook options
 * @param options.sync - Use sync() instead of validate() for online apps
 *
 * @example
 * ```tsx
 * // Offline-first (default)
 * function App() {
 *   const { isLicensed, tier, activate, loading } = useLicense();
 *
 *   if (loading) return <div>Loading...</div>;
 *
 *   if (!isLicensed) {
 *     return (
 *       <div>
 *         <p>Please enter your license key</p>
 *         <input onKeyDown={async (e) => {
 *           if (e.key === 'Enter') {
 *             await activate(e.currentTarget.value);
 *           }
 *         }} />
 *       </div>
 *     );
 *   }
 *
 *   return <div>Welcome! Your tier: {tier}</div>;
 * }
 *
 * // Online/subscription apps
 * function SubscriptionApp() {
 *   const { isLicensed, synced, offline, tier } = useLicense({ sync: true });
 *
 *   if (offline) {
 *     showToast('Offline mode - using cached license');
 *   }
 *
 *   return <div>Tier: {tier}</div>;
 * }
 * ```
 */
export function useLicense(options: UseLicenseOptions = {}): UseLicenseResult {
  const paycheck = usePaycheck();
  const { sync: useSync = false } = options;

  const [license, setLicense] = useState<LicenseClaims | null>(null);
  const [loading, setLoading] = useState(true);
  const [isLicensed, setIsLicensed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [synced, setSynced] = useState(false);
  const [offline, setOffline] = useState(false);

  // Load and validate license with Ed25519 signature verification
  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      if (useSync) {
        // Use sync() for online apps
        const result = await paycheck.sync();
        setLicense(result.claims ?? null);
        setIsLicensed(result.valid);
        setSynced(result.synced);
        setOffline(result.offline);
        if (!result.valid && result.reason) {
          setError(result.reason);
        }
      } else {
        // Use validate() for offline-first apps
        const result = await paycheck.validate();
        setLicense(result.claims ?? null);
        setIsLicensed(result.valid);
        setSynced(false);
        setOffline(true);
        if (!result.valid && result.reason) {
          setError(result.reason);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Validation failed');
      setIsLicensed(false);
    } finally {
      setLoading(false);
    }
  }, [paycheck, useSync]);

  // Initial load
  useEffect(() => {
    reload();
  }, [reload]);

  // Listen for cross-tab license changes (e.g., user clicked activation link in another tab)
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const handleStorage = (e: StorageEvent) => {
      if (e.key?.includes('paycheck')) {
        reload();
      }
    };

    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, [reload]);

  // Derived state
  const tier = license?.tier ?? null;
  const features = license?.features ?? [];
  const isExpired = paycheck.isExpired();

  // Actions
  const activateWithCode = useCallback(
    async (code: string, deviceInfo?: DeviceInfo): Promise<ActivationResult> => {
      setLoading(true);
      try {
        const result = await paycheck.activateWithCode(code, deviceInfo);
        await reload();
        return result;
      } finally {
        setLoading(false);
      }
    },
    [paycheck, reload]
  );

  const importToken = useCallback(
    async (token: string): Promise<ImportResult> => {
      setLoading(true);
      try {
        const result = await paycheck.importToken(token);
        await reload();
        return result;
      } finally {
        setLoading(false);
      }
    },
    [paycheck, reload]
  );

  const requestActivationCode = useCallback(
    async (email: string): Promise<RequestCodeResult> => {
      return paycheck.requestActivationCode(email);
    },
    [paycheck]
  );

  const refresh = useCallback(async (): Promise<string> => {
    setLoading(true);
    try {
      const token = await paycheck.refreshToken();
      await reload();
      return token;
    } finally {
      setLoading(false);
    }
  }, [paycheck, reload]);

  const deactivate = useCallback(async (): Promise<DeactivateResult> => {
    setLoading(true);
    try {
      const result = await paycheck.deactivate();
      await reload();
      return result;
    } finally {
      setLoading(false);
    }
  }, [paycheck, reload]);

  const clear = useCallback(() => {
    paycheck.clearToken();
    setLicense(null);
    setIsLicensed(false);
    setError(null);
    setSynced(false);
    setOffline(false);
  }, [paycheck]);

  return {
    license,
    loading,
    isLicensed,
    tier,
    features,
    isExpired,
    error,
    synced,
    offline,
    activateWithCode,
    importToken,
    requestActivationCode,
    refresh,
    deactivate,
    clear,
    reload,
  };
}

/**
 * Return type for useLicenseStatus hook
 */
export interface UseLicenseStatusResult {
  /** Whether there's a valid, non-expired license */
  isLicensed: boolean;
  /** Whether the license has expired */
  isExpired: boolean;
  /** Current tier (null if no license) */
  tier: string | null;
  /** Loading state */
  loading: boolean;
}

/**
 * Simple hook for checking license status.
 * Use this when you only need boolean checks, not the full license data.
 *
 * @example
 * ```tsx
 * function UpgradeButton() {
 *   const { isLicensed, tier, loading } = useLicenseStatus();
 *
 *   if (loading) return null;
 *
 *   if (isLicensed && tier === 'pro') {
 *     return null; // Already pro
 *   }
 *
 *   return <button>Upgrade to Pro</button>;
 * }
 * ```
 */
export function useLicenseStatus(): UseLicenseStatusResult {
  const paycheck = usePaycheck();

  const [status, setStatus] = useState<UseLicenseStatusResult>({
    isLicensed: false,
    isExpired: true,
    tier: null,
    loading: true,
  });

  useEffect(() => {
    async function checkStatus() {
      const result = await paycheck.validate();
      setStatus({
        isLicensed: result.valid,
        isExpired: paycheck.isExpired(),
        tier: paycheck.getTier(),
        loading: false,
      });
    }
    checkStatus();
  }, [paycheck]);

  return status;
}

/**
 * Hook for checking if a feature is enabled.
 *
 * @param feature - Feature name to check
 * @returns Whether the feature is enabled
 *
 * @example
 * ```tsx
 * function ExportButton() {
 *   const hasExport = useFeature('export');
 *
 *   if (!hasExport) {
 *     return <button disabled>Export (Pro only)</button>;
 *   }
 *
 *   return <button onClick={handleExport}>Export</button>;
 * }
 * ```
 */
export function useFeature(feature: string): boolean {
  const paycheck = usePaycheck();
  const [hasFeature, setHasFeature] = useState(false);

  useEffect(() => {
    setHasFeature(paycheck.hasFeature(feature));
  }, [paycheck, feature]);

  return hasFeature;
}

/**
 * Hook for checking if a version is covered by the license.
 *
 * @param versionTimestamp - Unix timestamp of the version release
 * @returns Whether the version is covered
 *
 * @example
 * ```tsx
 * const VERSION_TIMESTAMP = 1704067200; // Jan 1, 2024
 *
 * function App() {
 *   const hasAccess = useVersionAccess(VERSION_TIMESTAMP);
 *
 *   if (!hasAccess) {
 *     return <div>Please upgrade to access this version</div>;
 *   }
 *
 *   return <div>Welcome to v2.0!</div>;
 * }
 * ```
 */
export function useVersionAccess(versionTimestamp: number): boolean {
  const paycheck = usePaycheck();
  const [hasAccess, setHasAccess] = useState(false);

  useEffect(() => {
    setHasAccess(paycheck.coversVersion(versionTimestamp));
  }, [paycheck, versionTimestamp]);

  return hasAccess;
}

/**
 * Props for FeatureGate component
 */
export interface FeatureGateProps {
  /** Feature name to check */
  feature: string;
  /** Content to show when feature is enabled */
  children: React.ReactNode;
  /** Content to show when feature is disabled (optional) */
  fallback?: React.ReactNode;
}

/**
 * Component for gating content behind a feature.
 *
 * @example
 * ```tsx
 * <FeatureGate feature="export" fallback={<UpgradePrompt />}>
 *   <ExportButton />
 * </FeatureGate>
 * ```
 */
export function FeatureGate({
  feature,
  children,
  fallback = null,
}: FeatureGateProps): React.ReactNode {
  const hasFeature = useFeature(feature);
  return hasFeature ? children : fallback;
}

/**
 * Props for LicenseGate component
 */
export interface LicenseGateProps {
  /** Content to show when licensed */
  children: React.ReactNode;
  /** Content to show when not licensed (optional) */
  fallback?: React.ReactNode;
  /** Content to show while loading (optional) */
  loading?: React.ReactNode;
}

/**
 * Component for gating content behind a valid license.
 *
 * @example
 * ```tsx
 * <LicenseGate
 *   fallback={<PurchasePage />}
 *   loading={<Spinner />}
 * >
 *   <App />
 * </LicenseGate>
 * ```
 */
export function LicenseGate({
  children,
  fallback = null,
  loading: loadingContent = null,
}: LicenseGateProps): React.ReactNode {
  const { isLicensed, loading } = useLicenseStatus();

  if (loading) {
    return loadingContent;
  }

  return isLicensed ? children : fallback;
}

// ==================== Payment Callback Hook ====================

/**
 * Options for usePaymentCallback hook
 */
export interface UsePaymentCallbackOptions {
  /** Custom URL to check (default: window.location.href) */
  url?: string;
  /** Clean URL params after successful activation (default: true) */
  cleanUrl?: boolean;
  /** Path to replace URL with after activation (default: keeps current path) */
  redirectTo?: string;
  /** Device info for activation */
  deviceInfo?: DeviceInfo;
  /** Callback when activation succeeds */
  onSuccess?: (result: CallbackActivationResult) => void;
  /** Callback when activation fails */
  onError?: (error: string) => void;
  /** Skip automatic activation (manual control) */
  manual?: boolean;
}

/**
 * Return type for usePaymentCallback hook
 */
export interface UsePaymentCallbackResult {
  /** Whether callback processing is in progress */
  processing: boolean;
  /** Whether activation was successful */
  activated: boolean;
  /** Whether the current URL is a callback URL */
  isCallback: boolean;
  /** The activation result if successful */
  result: CallbackActivationResult | null;
  /** Error message if activation failed */
  error: string | null;
  /** Decoded license claims if activated */
  claims: LicenseClaims | null;
  /** Manually trigger activation (when manual: true) */
  activate: () => Promise<CallbackActivationResult>;
  /** Reset state (useful for retrying) */
  reset: () => void;
}

/**
 * Hook for seamlessly handling payment callbacks.
 *
 * Automatically detects if the current URL is a payment callback,
 * extracts the activation code, and completes activation in one step.
 *
 * @param options - Hook options
 *
 * @example
 * ```tsx
 * // Basic usage - just drop it in your callback page
 * function SuccessPage() {
 *   const { processing, activated, error, claims } = usePaymentCallback();
 *
 *   if (processing) {
 *     return <div>Activating your license...</div>;
 *   }
 *
 *   if (error) {
 *     return <div>Activation failed: {error}</div>;
 *   }
 *
 *   if (activated) {
 *     return <div>Welcome! Your tier: {claims?.tier}</div>;
 *   }
 *
 *   // Not a callback URL - show normal content
 *   return <div>Success page</div>;
 * }
 * ```
 *
 * @example
 * ```tsx
 * // With redirect after activation
 * function CallbackPage() {
 *   const { processing, activated } = usePaymentCallback({
 *     redirectTo: '/dashboard',
 *     onSuccess: (result) => {
 *       toast.success(`Welcome! You now have ${result.claims?.tier} access.`);
 *     },
 *     onError: (error) => {
 *       toast.error(`Activation failed: ${error}`);
 *     },
 *   });
 *
 *   if (processing) return <ActivationSpinner />;
 *   if (activated) return <Redirect to="/dashboard" />;
 *
 *   return <NormalPageContent />;
 * }
 * ```
 *
 * @example
 * ```tsx
 * // Manual control - activate when ready
 * function ManualCallbackPage() {
 *   const { isCallback, activate, processing, activated } = usePaymentCallback({
 *     manual: true,
 *   });
 *
 *   if (!isCallback) return <div>Not a callback</div>;
 *
 *   return (
 *     <div>
 *       <h1>Complete Your Purchase</h1>
 *       <button onClick={activate} disabled={processing}>
 *         {processing ? 'Activating...' : 'Activate License'}
 *       </button>
 *       {activated && <div>Success!</div>}
 *     </div>
 *   );
 * }
 * ```
 */
export function usePaymentCallback(
  options: UsePaymentCallbackOptions = {}
): UsePaymentCallbackResult {
  const paycheck = usePaycheck();
  const {
    url,
    cleanUrl = true,
    redirectTo,
    deviceInfo,
    onSuccess,
    onError,
    manual = false,
  } = options;

  const [processing, setProcessing] = useState(!manual);
  const [activated, setActivated] = useState(false);
  const [isCallback, setIsCallback] = useState(false);
  const [result, setResult] = useState<CallbackActivationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [claims, setClaims] = useState<LicenseClaims | null>(null);

  // Track if we've already processed to prevent double-activation
  const processedRef = useRef(false);

  // Get the URL to check
  const getUrl = useCallback(() => {
    if (url) return url;
    if (typeof window !== 'undefined') return window.location.href;
    return '';
  }, [url]);

  // Clean URL after activation
  const cleanUrlParams = useCallback(() => {
    if (typeof window === 'undefined') return;

    const targetPath = redirectTo || window.location.pathname;
    window.history.replaceState({}, '', targetPath);
  }, [redirectTo]);

  // Perform activation
  const activate = useCallback(async (): Promise<CallbackActivationResult> => {
    const currentUrl = getUrl();
    if (!currentUrl) {
      const noUrlResult: CallbackActivationResult = {
        activated: false,
        wasCallback: false,
        status: 'none',
        error: 'No URL available',
      };
      return noUrlResult;
    }

    setProcessing(true);
    setError(null);

    try {
      const activationResult = await paycheck.handleCallbackAndActivate(
        currentUrl,
        deviceInfo
      );

      setResult(activationResult);
      setIsCallback(activationResult.wasCallback);
      setActivated(activationResult.activated);

      if (activationResult.claims) {
        setClaims(activationResult.claims);
      }

      if (activationResult.activated) {
        if (cleanUrl) {
          cleanUrlParams();
        }
        onSuccess?.(activationResult);
      } else if (activationResult.wasCallback && activationResult.error) {
        setError(activationResult.error);
        onError?.(activationResult.error);
      }

      return activationResult;
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : 'Activation failed';
      setError(errorMessage);
      onError?.(errorMessage);

      const errorResult: CallbackActivationResult = {
        activated: false,
        wasCallback: true,
        status: 'success',
        error: errorMessage,
      };
      setResult(errorResult);
      return errorResult;
    } finally {
      setProcessing(false);
    }
  }, [
    getUrl,
    paycheck,
    deviceInfo,
    cleanUrl,
    cleanUrlParams,
    onSuccess,
    onError,
  ]);

  // Reset state
  const reset = useCallback(() => {
    setProcessing(false);
    setActivated(false);
    setIsCallback(false);
    setResult(null);
    setError(null);
    setClaims(null);
    processedRef.current = false;
  }, []);

  // Auto-activate on mount (unless manual mode)
  useEffect(() => {
    if (manual || processedRef.current) {
      setProcessing(false);
      return;
    }

    // Check if URL has callback params before processing
    const currentUrl = getUrl();
    if (!currentUrl) {
      setProcessing(false);
      return;
    }

    // Quick check for code param
    try {
      const urlObj = new URL(currentUrl);
      const hasCode = urlObj.searchParams.has('code');
      setIsCallback(hasCode);

      if (!hasCode) {
        setProcessing(false);
        return;
      }
    } catch {
      setProcessing(false);
      return;
    }

    // Process callback
    processedRef.current = true;
    activate();
  }, [manual, getUrl, activate]);

  return {
    processing,
    activated,
    isCallback,
    result,
    error,
    claims,
    activate,
    reset,
  };
}
