import { bench, describe } from 'bun:test';
import { hotp, totp, generateSecret, base32Encode, base32Decode } from '../src/index';

const secret = generateSecret();

describe('TOTP', () => {
  bench('generate 6-digit token (SHA1)', async () => {
    await totp({ secret, timestamp: 0 });
  });

  bench('generate 8-digit token (SHA256)', async () => {
    await totp({ secret, timestamp: 0, digits: 8, algorithm: 'SHA256' });
  });

  bench('generate 6-digit token (SHA512)', async () => {
    await totp({ secret, timestamp: 0, algorithm: 'SHA512' });
  });

  bench('verify valid token', async () => {
    const token = await totp({ secret, timestamp: 0 });
    await totp.verify({ secret, token, timestamp: 0, window: 1 });
  });
});

describe('HOTP', () => {
  bench('generate token (SHA1)', async () => {
    await hotp({ secret, counter: 0 });
  });

  bench('verify with window=10', async () => {
    const token = await hotp({ secret, counter: 100 });
    await hotp.verify({ secret, counter: 95, token, window: 10 });
  });
});

describe('Base32', () => {
  const raw = new Uint8Array(64);
  const encoded = base32Encode(raw);

  bench('encode 64 bytes', () => {
    base32Encode(raw);
  });

  bench('decode 104 chars', () => {
    base32Decode(encoded);
  });
});

describe('Secret generation', () => {
  bench('generate 20-byte secret', () => {
    generateSecret(20);
  });

  bench('generate 32-byte secret', () => {
    generateSecret(32);
  });
});
