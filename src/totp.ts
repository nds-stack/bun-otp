import { hotp } from './hotp.js';
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

async function totpFn(options: TOTPOptions): Promise<string> {
  const { secret, period = 30, digits = 6, algorithm = 'SHA1', timestamp } = options;
  validatePeriodAndDigits(period, digits);

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

  const time = timestamp ?? Date.now();
  const counter = Math.floor(time / 1000 / period);

  for (let i = -win; i <= win; i++) {
    const checkCounter = counter + i;
    const generated = await hotp({
      secret,
      counter: checkCounter,
      digits,
      algorithm,
    });
    if (timingSafeEqual(generated, token)) return true;
  }
  return false;
}

export const totp = Object.assign(totpFn, { verify: totpVerify });
