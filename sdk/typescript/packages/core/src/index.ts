// Main client
export { Paycheck, createPaycheck } from './paycheck';
export type {
  PaycheckOptions,
  OfflineValidateResult,
  SyncResult,
  ImportResult,
} from './paycheck';

// Types
export type {
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
  LicenseDeviceInfo,
  DeactivateResult,
  PaycheckErrorCode,
} from './types';
export { PaycheckError } from './types';

// Storage utilities
export {
  createLocalStorageAdapter,
  createMemoryStorage,
  generateUUID,
} from './storage';

// JWT utilities
export {
  decodeToken,
  verifyToken,
  verifyAndDecodeToken,
  isJwtExpired,
  isLicenseExpired,
  coversVersion,
  hasFeature,
} from './jwt';
