import { describe } from 'bun:test';
import { hotp, totp, generateSecret, base32Encode, base32Decode } from '../src/index.ts';

const secret = generateSecret(20);
const baselineKey = new Uint8Array(20);
crypto.getRandomValues(baselineKey);
const baselineData = new Uint8Array(8);

async function measure(label: string, fn: () => unknown, iterations = 1000) {
  const ret = fn();
  const isAsync = ret instanceof Promise;

  if (isAsync) {
    const start = performance.now();
    for (let i = 0; i < iterations; i++) await (fn as () => Promise<unknown>)();
    const ops = Math.round(iterations / ((performance.now() - start) / 1000));
    console.log(`  ${label.padEnd(50)} ${ops.toLocaleString().padStart(10)} ops/s`);
  } else {
    const start = performance.now();
    for (let i = 0; i < iterations; i++) (fn as () => void)();
    const ops = Math.round(iterations / ((performance.now() - start) / 1000));
    console.log(`  ${label.padEnd(50)} ${ops.toLocaleString().padStart(10)} ops/s`);
  }
}

describe('OTP Benchmarks', async () => {
  console.log(`\nBenchmark: @nds-stack/bun-otp vs competitors\n`);
  console.log('='.repeat(65));

  const hmacKey = await crypto.subtle.importKey('raw', baselineKey, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  await measure('baseline: crypto.subtle.sign', () => crypto.subtle.sign('HMAC', hmacKey, baselineData), 200);

  await measure('bun-otp: totp SHA1', () => totp({ secret, timestamp: 50000 }));
  await measure('bun-otp: totp SHA256', () => totp({ secret, timestamp: 50000, digits: 8, algorithm: 'SHA256' }));
  await measure('bun-otp: hotp SHA1', () => hotp({ secret, counter: 0 }));
  await measure('bun-otp: totp.verify window=1', async () => {
    const token = await totp({ secret, timestamp: 50000 });
    await totp.verify({ secret, token, timestamp: 50000, window: 1 });
  });
  await measure('bun-otp: base32Encode 64B', () => base32Encode(new Uint8Array(64)), 5000);
  await measure('bun-otp: base32Decode 104ch', () => base32Decode(base32Encode(new Uint8Array(64))), 5000);

  try {
    const m: { default?: Record<string, unknown>; generateSecret: () => { base32: string }; totp: (o: Record<string, unknown>) => string; hotp: (o: Record<string, unknown>) => string } = await import('speakeasy');
    const s = m.default || m;
    const ss = s.generateSecret().base32;
    await measure('speakeasy: totp SHA1', () => s.totp({ secret: ss, encoding: 'base32' }));
    await measure('speakeasy: totp SHA256', () => s.totp({ secret: ss, encoding: 'base32', algorithm: 'sha256' }));
    await measure('speakeasy: hotp SHA1', () => s.hotp({ secret: ss, counter: 0, encoding: 'base32' }));
  } catch (e) { console.log('  speakeasy: ERROR —', (e as Error).message); }

  try {
    const m: { generate: (o: Record<string, unknown>) => Promise<string>; verify: (o: Record<string, unknown>) => Promise<{ valid: boolean }> } = await import('otplib');
    await measure('otplib: totp SHA1', () => m.generate({ secret }));
    await measure('otplib: totp SHA256', () => m.generate({ secret, algorithm: 'sha256' }));
    await measure('otplib: hotp SHA1', () => m.generate({ secret, counter: 0 }));
    const token = await m.generate({ secret });
    await measure('otplib: totp.verify window=1', () => m.verify({ secret, token }));
  } catch (e) { console.log('  otplib: ERROR —', (e as Error).message); }

  try {
    const m: { generateTOTP: (o: Record<string, unknown>) => Promise<{ otp: string }>; verifyTOTP: (o: Record<string, unknown>) => Promise<{ delta: number } | null> } = await import('@epic-web/totp');
    await measure('@epic-web/totp: totp SHA1', () => m.generateTOTP({ algorithm: 'SHA1', secret }));
    await measure('@epic-web/totp: totp SHA256', () => m.generateTOTP({ algorithm: 'SHA256', secret }));
    const { otp } = await m.generateTOTP({ algorithm: 'SHA1', secret });
    await measure('@epic-web/totp: totp.verify window=1', () => m.verifyTOTP({ otp, secret, algorithm: 'SHA1', window: 1 }));
  } catch (e) { console.log('  @epic-web/totp: ERROR —', (e as Error).message); }

  console.log('='.repeat(65));
  console.log(`Note: Sync libs measured without await (tight loop). Async libs via await.`);
});
