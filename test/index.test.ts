import { describe, expect, test } from 'bun:test';
import { generateSecret, totp, hotp } from '../src/index.ts';

describe('base32', () => {
  test('generateSecret produces valid base32 string', () => {
    const secret = generateSecret();
    expect(secret.length).toBeGreaterThan(0);
    expect(secret).toMatch(/^[A-Z2-7]+=*$/);
  });
});

describe('TOTP', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  test('generates 6-digit token', async () => {
    const token = await totp({ secret, timestamp: 0 });
    expect(token).toHaveLength(6);
    expect(/^\d{6}$/.test(token)).toBe(true);
  });

  test('generates 8-digit token', async () => {
    const token = await totp({ secret, digits: 8, timestamp: 0 });
    expect(token).toHaveLength(8);
    expect(/^\d{8}$/.test(token)).toBe(true);
  });

  test('SHA256 algorithm works', async () => {
    const token = await totp({ secret, algorithm: 'SHA256', timestamp: 0 });
    expect(token).toHaveLength(6);
  });

  test('SHA512 algorithm works', async () => {
    const token = await totp({ secret, algorithm: 'SHA512', timestamp: 0 });
    expect(token).toHaveLength(6);
  });

  test('verify returns true for valid token', async () => {
    const token = await totp({ secret, timestamp: 0 });
    const valid = await totp.verify({ secret, token, timestamp: 0 });
    expect(valid).toBe(true);
  });

  test('verify returns false for invalid token', async () => {
    const valid = await totp.verify({ secret, token: '000000', timestamp: 0 });
    expect(valid).toBe(false);
  });

  test('verify with window=1 accepts adjacent periods', async () => {
    const token = await totp({ secret, timestamp: 0 });
    const valid = await totp.verify({
      secret,
      token,
      timestamp: 30000,
      window: 1,
    });
    expect(valid).toBe(true);
  });

  test('same secret + same time = same token', async () => {
    const token1 = await totp({ secret, timestamp: 1000000 });
    const token2 = await totp({ secret, timestamp: 1000000 });
    expect(token1).toBe(token2);
  });

  test('RFC 6238 test vector — time=59, 8 digits', async () => {
    const token = await totp({
      secret,
      timestamp: 59000,
      digits: 8,
      algorithm: 'SHA1',
    });
    expect(token).toBe('94287082');
  });

  test('RFC 6238 test vector — time=1111111109, 8 digits', async () => {
    const token = await totp({
      secret,
      timestamp: 1111111109000,
      digits: 8,
      algorithm: 'SHA1',
    });
    expect(token).toBe('07081804');
  });

  test('token is exactly `digits` long (no leading zeros stripped)', async () => {
    const token = await totp({
      secret,
      timestamp: 1111111109000,
      digits: 8,
      algorithm: 'SHA1',
    });
    expect(token).toHaveLength(8);
    expect(token).toBe('07081804');
  });
});

describe('HOTP', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  test('generates token for counter=0', async () => {
    const token = await hotp({ secret, counter: 0 });
    expect(token).toHaveLength(6);
    expect(/^\d{6}$/.test(token)).toBe(true);
  });

  test('generates token for counter=9999', async () => {
    const token = await hotp({ secret, counter: 9999 });
    expect(token).toHaveLength(6);
  });

  test('verify returns true for valid token', async () => {
    const token = await hotp({ secret, counter: 42 });
    const valid = await hotp.verify({ secret, counter: 42, token });
    expect(valid).toBe(true);
  });

  test('verify with window accepts look-ahead', async () => {
    const token = await hotp({ secret, counter: 100 });
    const valid = await hotp.verify({
      secret,
      counter: 99,
      token,
      window: 1,
    });
    expect(valid).toBe(true);
  });

  test('different secrets produce different tokens', async () => {
    const token1 = await hotp({ secret, counter: 5 });
    const token2 = await hotp({ secret: 'AAAAAAAAAAAAAAAA', counter: 5 });
    expect(token1).not.toBe(token2);
  });

  test('RFC 4226 test vectors', async () => {
    const vectors = [
      [0, '755224'], [1, '287082'], [2, '359152'],
      [3, '969429'], [4, '338314'], [5, '254676'],
      [6, '287922'], [7, '162583'], [8, '399871'],
      [9, '520489'],
    ] as const;
    for (const [counter, expected] of vectors) {
      const token = await hotp({ secret, counter, digits: 6 });
      expect(token).toBe(expected);
    }
  });
});

describe('Error handling', () => {
  test('throws on invalid base32 secret', async () => {
    expect(hotp({ secret: '!!!!', counter: 0 })).rejects.toThrow();
  });

  test('throws on negative counter', async () => {
    expect(hotp({ secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', counter: -1 })).rejects.toThrow();
  });

  test('throws on digits out of range', async () => {
    expect(hotp({ secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', counter: 0, digits: 0 })).rejects.toThrow();
    expect(hotp({ secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', counter: 0, digits: 11 })).rejects.toThrow();
  });

  test('throws on window exceeding max', async () => {
    const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    const token = await hotp({ secret, counter: 0 });
    expect(hotp.verify({ secret, counter: 0, token, window: 99 })).rejects.toThrow();
    expect(totp.verify({ secret, token, timestamp: 0, window: 99 })).rejects.toThrow();
  });

  test('throws on empty secret', async () => {
    expect(hotp({ secret: '', counter: 0 })).rejects.toThrow();
  });

  test('throws on NaN timestamp', async () => {
    expect(totp({ secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', timestamp: NaN })).rejects.toThrow();
  });
});
