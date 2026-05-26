import { describe } from 'bun:test';
import { hotp, totp, generateSecret, base32Encode, base32Decode } from '../src/index.ts';

const secret = generateSecret();
const baselineKey = new Uint8Array(20);
crypto.getRandomValues(baselineKey);
const baselineData = new Uint8Array(8);

async function run(label: string, fn: () => Promise<unknown> | unknown, iterations = 1000) {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) await fn();
  const elapsed = performance.now() - start;
  const opsPerSec = Math.round(iterations / (elapsed / 1000));
  console.log(`  ${label.padEnd(55)} ${opsPerSec.toLocaleString().padStart(12)} ops/s`);
}

describe('OTP Benchmarks', async () => {
  console.log(`\nBenchmark: @nds-stack/bun-otp (1000 iterations each)\n`);
  console.log('='.repeat(72));

  // Baseline
  await run('baseline: crypto.subtle.sign (SHA1)', async () => {
    const k = await crypto.subtle.importKey('raw', baselineKey, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    await crypto.subtle.sign('HMAC', k, baselineData);
  });

  // TOTP
  await run('totp() 6-digit SHA1', () => totp({ secret, timestamp: 50000 }));
  await run('totp() 8-digit SHA256', () => totp({ secret, timestamp: 50000, digits: 8, algorithm: 'SHA256' }));
  await run('totp() 6-digit SHA512', () => totp({ secret, timestamp: 50000, algorithm: 'SHA512' }));
  await run('totp.verify() window=1', async () => {
    const token = await totp({ secret, timestamp: 50000 });
    await totp.verify({ secret, token, timestamp: 50000, window: 1 });
  });

  // HOTP
  await run('hotp() SHA1', () => hotp({ secret, counter: 0 }));
  await run('hotp.verify() window=10', async () => {
    const token = await hotp({ secret, counter: 100 });
    await hotp.verify({ secret, counter: 95, token, window: 10 });
  });

  // Base32
  const raw = new Uint8Array(64);
  const encoded = base32Encode(raw);
  await run('base32Encode(64 bytes)', () => base32Encode(raw));
  await run('base32Decode(104 chars)', () => base32Decode(encoded));

  // Secret generation
  await run('generateSecret(20)', () => generateSecret(20));
  await run('generateSecret(32)', () => generateSecret(32));

  console.log('='.repeat(72));
});
