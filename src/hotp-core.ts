import { hmacSign } from './hmac.js';

const STEAM_ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';

function counterToBytes(counter: number): Uint8Array {
  const bytes = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    bytes[i] = c & 0xff;
    c >>>= 8;
  }
  return bytes;
}

function getBinaryCode(key: Uint8Array, counter: number, algorithm: 'SHA1' | 'SHA256' | 'SHA512'): number {
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
  return code >>> 0;
}

export function hotpCore(key: Uint8Array, counter: number, digits: number, algorithm: 'SHA1' | 'SHA256' | 'SHA512'): string {
  const code = getBinaryCode(key, counter, algorithm);
  const otp = code % (10 ** digits);
  return otp.toString().padStart(digits, '0');
}

export function steamTotp(key: Uint8Array, timestamp: number, algorithm: 'SHA1' | 'SHA256' | 'SHA512' = 'SHA1'): string {
  const counter = Math.floor(timestamp / 1000 / 30);
  const code = getBinaryCode(key, counter, algorithm);
  let result = '';
  let remaining = code;
  for (let i = 0; i < 5; i++) {
    result = STEAM_ALPHABET[remaining % STEAM_ALPHABET.length] + result;
    remaining = Math.floor(remaining / STEAM_ALPHABET.length);
  }
  return result;
}
