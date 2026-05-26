import { hmacSign } from './hmac.js';

function counterToBytes(counter: number): Uint8Array {
  const bytes = new Uint8Array(8);
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    bytes[i] = Number(c & 0xffn);
    c >>= 8n;
  }
  return bytes;
}

export function hotpCore(key: Uint8Array, counter: number, digits: number, algorithm: 'SHA1' | 'SHA256' | 'SHA512'): string {
  if (!Number.isInteger(digits) || digits < 1 || digits > 10) {
    throw new RangeError(`digits must be 1-10, got ${digits}`);
  }
  if (!Number.isInteger(counter) || counter < 0 || counter > Number.MAX_SAFE_INTEGER) {
    throw new RangeError(`counter must be a non-negative integer, got ${counter}`);
  }
  const counterData = counterToBytes(counter);
  const hmacResult = hmacSign(key, counterData, algorithm);
  const offset = hmacResult[hmacResult.length - 1] & 0xf;
  const code =
    ((hmacResult[offset] & 0x7f) << 24) |
    (hmacResult[offset + 1] << 16) |
    (hmacResult[offset + 2] << 8) |
    hmacResult[offset + 3];
  const otp = (code >>> 0) % (10 ** digits);
  return otp.toString().padStart(digits, '0');
}
