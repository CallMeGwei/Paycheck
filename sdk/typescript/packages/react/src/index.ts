// Provider
export { PaycheckProvider, usePaycheck } from './provider';
export type { PaycheckProviderProps } from './provider';

// Hooks
export {
  useLicense,
  useLicenseStatus,
  useFeature,
  useVersionAccess,
} from './hooks';
export type {
  UseLicenseOptions,
  UseLicenseResult,
  UseLicenseStatusResult,
} from './hooks';

// Gate components
export { FeatureGate, LicenseGate } from './hooks';
export type { FeatureGateProps, LicenseGateProps } from './hooks';

// Re-export types from core that are commonly needed
export type {
  PaycheckOptions,
  LicenseClaims,
  ActivationResult,
  DeactivateResult,
  DeviceInfo,
  ImportResult,
  SyncResult,
  PaycheckErrorCode,
} from '@paycheck/sdk';
export { Paycheck, PaycheckError } from '@paycheck/sdk';
