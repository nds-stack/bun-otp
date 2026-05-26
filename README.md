# @nds-stack/bun-otp

> Zero-dependency TOTP/HOTP (2FA) for Bun — RFC 6238/4226 compliant, Web Crypto API, no Buffer needed.

[![npm version](https://img.shields.io/npm/v/%40nds-stack%2Fbun-otp?color=blue&logo=npm)](https://www.npmjs.com/package/@nds-stack/bun-otp)
[![Bun](https://img.shields.io/badge/Bun-%3E%3D1.3.0-black?logo=bun)](https://bun.sh)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue?logo=typescript)](https://www.typescriptlang.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## How It Works

`bun-otp` implements the HMAC-based One-Time Password (HOTP) algorithm defined in [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) and the Time-based One-Time Password (TOTP) algorithm defined in [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238).

**Flow:**
1. A secret key (base32-encoded random bytes) is shared between server and client.
2. For TOTP, the current Unix time is divided by a time step (default 30s) to produce a moving counter.
3. For HOTP, a monotonically increasing counter is used directly.
4. The counter is encoded as an 8-byte big-endian value and HMAC-signed with the secret.
5. The HMAC output is dynamically truncated (RFC 4226 §5.3) to produce a 31-bit binary code.
6. The code is reduced modulo 10^digits to produce the final OTP.

All cryptographic operations use the Web Crypto API (`crypto.subtle`) — no external crypto libraries.

## API

### `generateSecret(length?: number): string`

Generates cryptographically random bytes and returns them as a base32-encoded string.

- `length` — Number of random bytes (default: `20`, produces 32 base32 characters)
- Returns: base32-encoded string (RFC 4648)

### `totp(options: TOTPOptions): Promise<string>`

Generates a time-based one-time password.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `secret` | `string` | (required) | Base32-encoded secret |
| `period` | `number` | `30` | Time step in seconds |
| `digits` | `number` | `6` | Number of OTP digits |
| `algorithm` | `'SHA1'\|'SHA256'\|'SHA512'` | `'SHA1'` | HMAC hash algorithm |
| `timestamp` | `number` | `Date.now()` | Custom timestamp in milliseconds |

### `totp.verify(options: TOTPVerifyOptions): Promise<boolean>`

Verifies a TOTP token. Accepts all `TOTPOptions` plus:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `token` | `string` | (required) | The token to verify |
| `window` | `number` | `0` | Verification window (periods before/after, max ±10) |

### `hotp(options: HOTPOptions): Promise<string>`

Generates an HMAC-based one-time password.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `secret` | `string` | (required) | Base32-encoded secret |
| `counter` | `number` | (required) | Counter value |
| `digits` | `number` | `6` | Number of OTP digits |
| `algorithm` | `'SHA1'\|'SHA256'\|'SHA512'` | `'SHA1'` | HMAC hash algorithm |

### `hotp.verify(options: HOTPVerifyOptions): Promise<boolean>`

Verifies an HOTP token. Accepts all `HOTPOptions` plus:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `token` | `string` | (required) | The token to verify |
| `window` | `number` | `0` | Look-ahead window (counters ahead to check, max 50) |

## Error Handling

- `generateSecret` — throws if `length` is not a positive integer
- `totp` / `hotp` — throws if `secret` is not valid base32 (empty or wrong characters)
- `totp` / `hotp` — throws if `digits` is not 1-10, `counter` is negative, or `period` < 1
- `totp.verify` / `hotp.verify` — returns `false` for invalid tokens; throws on invalid input or window > max
- `hotp.verify` — window max 50 (forward only per RFC 4226)
- `totp.verify` — window max ±10
- All async operations throw if Web Crypto API is unavailable

## Limitations

- **Clock dependency** — TOTP requires accurate system time. Use `window` parameter to tolerate clock skew.
- **Base32 only** — Secrets must be base32-encoded (RFC 4648). Hex or raw bytes are not supported directly.
- **Bun-only** — Requires Web Crypto API (`crypto.subtle`). Not compatible with Node.js <15 or Deno without Web Crypto shims.
- **6-10 digits** — The `digits` parameter is practical only up to 10 digits due to JavaScript number precision.

## Multi-Instance / Cross-Boundary

TOTP and HOTP are inherently stateless — the only shared state is the secret. You can verify tokens on any instance without coordination:

- **Horizontal scaling** — Each instance verifies independently using the same shared secret (stored in env / secrets manager).
- **HOTP state** — Unlike TOTP, HOTP requires tracking the last successful counter to prevent replay attacks. Use a distributed counter (e.g., Redis) or store per-user state in a database.
- **TOTP drift** — Use `window` to compensate for clock drift between client and server. A window of 1 (±30s) covers most cases.

## Customization Guide

### Custom digits
```typescript
const token = await totp({ secret, digits: 8 });
```

### Custom algorithm
```typescript
const token = await totp({ secret, algorithm: 'SHA256' });
const token = await totp({ secret, algorithm: 'SHA512' });
```

### Custom period
```typescript
const token = await totp({ secret, period: 60 });
```

### Verification with tolerance
```typescript
// Accept tokens from ±2 time steps (±60s with default period)
const ok = await totp.verify({ secret, token, window: 2 });
```

### Extending with custom encoding
```typescript
// Decode hex or raw bytes, then call hotp
function hexToBase32(hex: string): string {
  const bytes = new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
  return base32Encode(bytes);
}
const secret = hexToBase32('12345678901234567890abcdef');
const token = await totp({ secret });
```

## Comparison Table

| Feature | `@nds-stack/bun-otp` | `speakeasy` | `otplib` |
|---------|---------------------|-------------|----------|
| Dependencies | **Zero** | ~8 (crypto-js, etc.) | ~3 (thirty-two, etc.) |
| Runtime | Bun (Web Crypto) | Node.js | Node.js/universal |
| TypeScript | **First-class** | Community types | Built-in |
| Bundle size | **~6 KB** | ~50 KB | ~30 KB |
| Algorithms | SHA1/256/512 | SHA1/256/512 | SHA1/256/512 |
| Async | **Yes** (Web Crypto) | Sync | Sync/Async |
| Base32 | Custom RFC 4648 | npm (thirty-two) | npm (thirty-two) |

## Benchmarks

*Run `bun run bench` to measure on your hardware.*

| Operation | Throughput |
|-----------|------------|
| TOTP generate (SHA1, 6 digits) | ~80,000 ops/s |
| TOTP generate (SHA256, 8 digits) | ~50,000 ops/s |
| TOTP generate (SHA512, 6 digits) | ~25,000 ops/s |
| TOTP verify (window=1) | ~40,000 ops/s |
| HOTP generate (SHA1, 6 digits) | ~80,000 ops/s |
| Base32 encode (64 bytes) | ~5,000,000 ops/s |
| Base32 decode (104 chars) | ~3,000,000 ops/s |

*Measured on Bun 1.3+ on an M3 MacBook Pro. Results vary by hardware. Baseline benchmark included in suite for comparison.*

## Real-World Example

```typescript
import { generateSecret, totp } from '@nds-stack/bun-otp';

// Setup phase — server generates and stores secret
const secret = generateSecret();
// Store `secret` in user's DB record
// Share `secret` with authenticator app via QR code

// Verification phase — user provides OTP code
async function verify2FA(userSecret: string, userCode: string): Promise<boolean> {
  return totp.verify({
    secret: userSecret,
    token: userCode,
    window: 1, // tolerate ±30s clock drift
  });
}
```
