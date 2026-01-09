'use client';

import React, { useState, useEffect, useCallback } from 'react';
import type {
  LicenseClaims,
  ActivationResult,
  DeactivateResult,
  DeviceInfo,
  ImportResult,
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
  /** Activate with license key */
  activate: (
    licenseKey: string,
    deviceInfo?: DeviceInfo
  ) => Promise<ActivationResult>;
  /** Activate with redemption code */
  activateWithCode: (
    code: string,
    deviceInfo?: DeviceInfo
  ) => Promise<ActivationResult>;
  /** Import a JWT token directly (offline activation) */
  importToken: (token: string) => Promise<ImportResult>;
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

  // Derived state
  const tier = license?.tier ?? null;
  const features = license?.features ?? [];
  const isExpired = paycheck.isExpired();

  // Actions
  const activate = useCallback(
    async (
      licenseKey: string,
      deviceInfo?: DeviceInfo
    ): Promise<ActivationResult> => {
      setLoading(true);
      try {
        const result = await paycheck.activate(licenseKey, deviceInfo);
        await reload();
        return result;
      } finally {
        setLoading(false);
      }
    },
    [paycheck, reload]
  );

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
    activate,
    activateWithCode,
    importToken,
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
