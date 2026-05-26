import { base32Decode } from './base32.js';
import { hotpCore } from './hotp-core.js';
import { timingSafeEqual } from './timing-safe-equal.js';
import type { HOTPOptions, HOTPVerifyOptions } from './types.js';

function hotpFn(options: HOTPOptions): string {
  const { secret, counter, digits = 6, algorithm = 'SHA1' } = options;

  if (!Number.isInteger(digits) || digits < 1 || digits > 10) {
    throw new RangeError(`HOTP: digits must be 1-10, got ${digits}`);
  }
  if (!Number.isInteger(counter) || counter < 0 || counter > Number.MAX_SAFE_INTEGER) {
    throw new RangeError(`HOTP: counter must be a non-negative integer, got ${counter}`);
  }

  const key = base32Decode(secret);
  return hotpCore(key, counter, digits, algorithm);
}

function hotpVerify(options: HOTPVerifyOptions): boolean {
  const {
    token,
    secret,
    counter,
    digits = 6,
    algorithm = 'SHA1',
    window: win = 0,
  } = options;

  if (!Number.isInteger(win) || win < 0 || win > 50) {
    throw new RangeError(`HOTP verify: window must be 0-50, got ${win}`);
  }
  if (!Number.isInteger(counter) || counter < 0 || counter > Number.MAX_SAFE_INTEGER) {
    throw new RangeError(`HOTP verify: counter must be a non-negative integer, got ${counter}`);
  }

  const key = base32Decode(secret);
  for (let i = 0; i <= win; i++) {
    if (timingSafeEqual(hotpCore(key, counter + i, digits, algorithm), token)) return true;
  }
  return false;
}

export const hotp = Object.assign(hotpFn, { verify: hotpVerify });
