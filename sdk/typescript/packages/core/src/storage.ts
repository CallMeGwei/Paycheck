import type { StorageAdapter } from './types';

/** Storage key prefix */
const PREFIX = 'paycheck:';

/** Storage keys */
export const STORAGE_KEYS = {
  TOKEN: `${PREFIX}token`,
  DEVICE_ID: `${PREFIX}device_id`,
} as const;

/**
 * Creates a localStorage-based storage adapter.
 * Falls back to memory storage if localStorage is unavailable.
 */
export function createLocalStorageAdapter(): StorageAdapter {
  // SSR/build context - silently use memory storage (expected behavior)
  if (typeof window === 'undefined') {
    return createMemoryStorage();
  }

  // Client-side check for localStorage availability
  const hasLocalStorage = (() => {
    try {
      const test = '__paycheck_test__';
      localStorage.setItem(test, test);
      localStorage.removeItem(test);
      return true;
    } catch {
      return false;
    }
  })();

  if (!hasLocalStorage) {
    // Only warn for actual client-side unavailability (private mode, quota exceeded, etc.)
    console.warn(
      '[Paycheck] localStorage unavailable, using in-memory storage. ' +
        'License state will not persist across page loads.'
    );
    return createMemoryStorage();
  }

  return {
    get(key: string): string | null {
      return localStorage.getItem(key);
    },
    set(key: string, value: string): void {
      localStorage.setItem(key, value);
    },
    remove(key: string): void {
      localStorage.removeItem(key);
    },
  };
}

/**
 * Creates an in-memory storage adapter.
 * Useful for SSR, testing, or environments without localStorage.
 */
export function createMemoryStorage(): StorageAdapter {
  const store = new Map<string, string>();

  return {
    get(key: string): string | null {
      return store.get(key) ?? null;
    },
    set(key: string, value: string): void {
      store.set(key, value);
    },
    remove(key: string): void {
      store.delete(key);
    },
  };
}

/**
 * Generates a random UUID v4
 */
export function generateUUID(): string {
  // Use crypto.randomUUID if available (modern browsers, Node 19+)
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }

  // Fallback to manual generation
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Gets or creates a persistent device ID
 */
export function getOrCreateDeviceId(storage: StorageAdapter): string {
  const stored = storage.get(STORAGE_KEYS.DEVICE_ID);

  // Handle async storage
  if (stored instanceof Promise) {
    throw new Error(
      'Cannot use async storage for device ID. ' +
        'Provide deviceId in config or use sync storage.'
    );
  }

  if (stored) {
    return stored;
  }

  const deviceId = generateUUID();
  storage.set(STORAGE_KEYS.DEVICE_ID, deviceId);
  return deviceId;
}
