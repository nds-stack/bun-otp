import { hotp, hotpCore } from './hotp.js';
import { base32Decode } from './base32.js';
import { timingSafeEqual } from './timing-safe-equal.js';
import type { TOTPOptions, TOTPVerifyOptions } from './types.js';

function validatePeriodAndDigits(period: number, digits: number): void {
  if (!Number.isFinite(period) || period < 1) {
    throw new RangeError(`TOTP: period must be >= 1, got ${period}`);
  }
  if (!Number.isInteger(digits) || digits < 1 || digits > 10) {
    throw new RangeError(`TOTP: digits must be 1-10, got ${digits}`);
  }
}

function validateWindow(win: number, max = 10): void {
  if (!Number.isInteger(win) || win < 0 || win > max) {
    throw new RangeError(`window must be 0-${max}, got ${win}`);
  }
}

async function totpFn(options: TOTPOptions): Promise<string> {
  const { secret, period = 30, digits = 6, algorithm = 'SHA1', timestamp } = options;
  validatePeriodAndDigits(period, digits);
  if (timestamp !== undefined && (!Number.isFinite(timestamp) || timestamp < 0)) {
    throw new RangeError(`TOTP: timestamp must be a non-negative number, got ${timestamp}`);
  }

  const time = timestamp ?? Date.now();
  const counter = Math.floor(time / 1000 / period);

  return hotp({ secret, counter, digits, algorithm });
}

async function totpVerify(options: TOTPVerifyOptions): Promise<boolean> {
  const {
    token,
    secret,
    period = 30,
    digits = 6,
    algorithm = 'SHA1',
    timestamp,
    window: win = 0,
  } = options;

  validatePeriodAndDigits(period, digits);
  validateWindow(win);
  if (timestamp !== undefined && (!Number.isFinite(timestamp) || timestamp < 0)) {
    throw new RangeError(`TOTP: timestamp must be a non-negative number, got ${timestamp}`);
  }

  const time = timestamp ?? Date.now();
  const counter = Math.floor(time / 1000 / period);

  const key = base32Decode(secret);
  for (let i = -win; i <= win; i++) {
    const checkCounter = counter + i;
    if (checkCounter < 0) continue;
    const generated = await hotpCore(key, checkCounter, digits, algorithm);
    if (timingSafeEqual(generated, token)) return true;
  }
  return false;
}

export const totp = Object.assign(totpFn, { verify: totpVerify });
