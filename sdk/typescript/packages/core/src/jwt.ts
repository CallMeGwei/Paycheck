import * as ed25519 from '@noble/ed25519';
import type { LicenseClaims } from './types';
import { PaycheckError } from './types';

/**
 * Decodes a base64url string to a regular string
 */
function base64urlDecode(str: string): string {
  // Replace base64url characters with base64 characters
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if needed
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }

  // Decode
  if (typeof atob !== 'undefined') {
    return atob(base64);
  }

  // Node.js fallback
  return Buffer.from(base64, 'base64').toString('utf-8');
}

/**
 * Decodes a base64url string to bytes
 */
function base64urlToBytes(str: string): Uint8Array {
  // Replace base64url characters with base64 characters
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if needed
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }

  // Decode to bytes
  if (typeof atob !== 'undefined') {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Node.js fallback
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

/**
 * Decodes a standard base64 string to bytes
 */
function base64ToBytes(str: string): Uint8Array {
  if (typeof atob !== 'undefined') {
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Node.js fallback
  return new Uint8Array(Buffer.from(str, 'base64'));
}

/**
 * Decodes a JWT and returns the claims.
 * Does NOT verify the signature (that's the server's job).
 */
export function decodeToken(token: string): LicenseClaims {
  const parts = token.split('.');

  if (parts.length !== 3) {
    throw new PaycheckError('VALIDATION_ERROR', 'Invalid JWT format');
  }

  try {
    const payload = base64urlDecode(parts[1]);
    return JSON.parse(payload) as LicenseClaims;
  } catch {
    throw new PaycheckError('VALIDATION_ERROR', 'Failed to decode JWT');
  }
}

/**
 * Checks if the JWT's exp claim has passed.
 * This is for transport security, not license validity.
 */
export function isJwtExpired(claims: LicenseClaims): boolean {
  const now = Math.floor(Date.now() / 1000);
  return claims.exp < now;
}

/**
 * Checks if the license has expired (license_exp claim).
 * This is the actual license validity check.
 */
export function isLicenseExpired(claims: LicenseClaims): boolean {
  if (claims.license_exp === null) {
    return false; // Perpetual license
  }
  const now = Math.floor(Date.now() / 1000);
  return claims.license_exp < now;
}

/**
 * Checks if the license covers a specific version (by its release timestamp).
 */
export function coversVersion(
  claims: LicenseClaims,
  versionTimestamp: number
): boolean {
  if (claims.updates_exp === null) {
    return true; // All versions covered
  }
  return versionTimestamp <= claims.updates_exp;
}

/**
 * Checks if the license has a specific feature.
 */
export function hasFeature(claims: LicenseClaims, feature: string): boolean {
  return claims.features.includes(feature);
}

/**
 * Verifies a JWT signature using Ed25519.
 * Returns true if the signature is valid, false otherwise.
 *
 * @param token - The JWT token to verify
 * @param publicKey - Base64-encoded Ed25519 public key
 */
export async function verifyToken(
  token: string,
  publicKey: string
): Promise<boolean> {
  const parts = token.split('.');

  if (parts.length !== 3) {
    return false;
  }

  try {
    // The message is the header.payload part
    const message = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const signature = base64urlToBytes(parts[2]);
    const publicKeyBytes = base64ToBytes(publicKey);

    // Verify the signature
    return await ed25519.verifyAsync(signature, message, publicKeyBytes);
  } catch {
    return false;
  }
}

/**
 * Verifies a JWT and returns the claims if valid.
 * Throws if signature verification fails.
 *
 * @param token - The JWT token to verify
 * @param publicKey - Base64-encoded Ed25519 public key
 */
export async function verifyAndDecodeToken(
  token: string,
  publicKey: string
): Promise<LicenseClaims> {
  const valid = await verifyToken(token, publicKey);

  if (!valid) {
    throw new PaycheckError('VALIDATION_ERROR', 'Invalid JWT signature');
  }

  return decodeToken(token);
}
