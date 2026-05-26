import { base32Encode } from './base32';

export function generateSecret(length: number = 20): string {
  if (!Number.isInteger(length) || length < 1) {
    throw new RangeError(`generateSecret: length must be a positive integer, got ${length}`);
  }
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}
