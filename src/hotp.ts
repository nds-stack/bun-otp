import { base32Decode } from './base32.js';
import { hmacSign } from './hmac.js';
import { timingSafeEqual } from './timing-safe-equal.js';
import type { HOTPOptions, HOTPVerifyOptions } from './types.js';

function counterToBytes(counter: number): Uint8Array {
  const bytes = new Uint8Array(8);
  let c = BigInt(Math.floor(counter));
  for (let i = 7; i >= 0; i--) {
    bytes[i] = Number(c & 0xffn);
    c >>= 8n;
  }
  return bytes;
}

function dynamicTruncate(hmacResult: Uint8Array): number {
  const offset = hmacResult[hmacResult.length - 1] & 0xf;
  const code =
    ((hmacResult[offset] & 0x7f) << 24) |
    (hmacResult[offset + 1] << 16) |
    (hmacResult[offset + 2] << 8) |
    hmacResult[offset + 3];
  return code >>> 0;
}

async function hotpFn(options: HOTPOptions): Promise<string> {
  const { secret, counter, digits = 6, algorithm = 'SHA1' } = options;

  const key = base32Decode(secret);
  const counterData = counterToBytes(counter);
  const hmacResult = await hmacSign(key, counterData, algorithm);
  const binaryCode = dynamicTruncate(hmacResult);
  const otp = binaryCode % Math.pow(10, digits);

  return otp.toString().padStart(digits, '0');
}

async function hotpVerify(options: HOTPVerifyOptions): Promise<boolean> {
  const {
    token,
    secret,
    counter,
    digits = 6,
    algorithm = 'SHA1',
    window: win = 0,
  } = options;

  for (let i = 0; i <= win; i++) {
    const generated = await hotpFn({
      secret,
      counter: counter + i,
      digits,
      algorithm,
    });
    if (timingSafeEqual(generated, token)) return true;
  }
  return false;
}

export const hotp = Object.assign(hotpFn, { verify: hotpVerify });
