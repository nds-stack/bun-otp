import { hmacSign } from './hmac.js';

function counterToBytes(counter: number): Uint8Array {
  const bytes = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    bytes[i] = c & 0xff;
    c >>>= 8;
  }
  return bytes;
}

export function hotpCore(key: Uint8Array, counter: number, digits: number, algorithm: 'SHA1' | 'SHA256' | 'SHA512'): string {
  const counterData = counterToBytes(counter);
  const hmacResult = hmacSign(key, counterData, algorithm);
  const offset = hmacResult[hmacResult.length - 1] & 0xf;
  if (offset + 3 >= hmacResult.length) {
    throw new Error('HMAC result too short for dynamic truncation');
  }
  const code =
    ((hmacResult[offset] & 0x7f) << 24) |
    (hmacResult[offset + 1] << 16) |
    (hmacResult[offset + 2] << 8) |
    hmacResult[offset + 3];
  const otp = (code >>> 0) % (10 ** digits);
  return otp.toString().padStart(digits, '0');
}
