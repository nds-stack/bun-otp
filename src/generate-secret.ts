import { base32Encode } from './base32.js';

export function generateSecret(length: number = 20): string {
  if (!Number.isInteger(length) || length < 1) {
    throw new RangeError(`generateSecret: length must be a positive integer, got ${length}`);
  }
  if (length > 65536) {
    throw new RangeError(`generateSecret: length must be ≤ 65536, got ${length}`);
  }
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}
