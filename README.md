# @nds-stack/bun-otp

> Zero-dependency TOTP/HOTP (2FA) for Bun — RFC 6238/4226 compliant, `Bun.CryptoHasher`, no Buffer needed.

[![npm version](https://img.shields.io/npm/v/%40nds-stack%2Fbun-otp?color=blue&logo=npm)](https://www.npmjs.com/package/@nds-stack/bun-otp) [![Bun](https://img.shields.io/badge/Bun-%3E%3D1.3.0-black?logo=bun)](https://bun.sh) [![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue?logo=typescript)](https://www.typescriptlang.org) [![License](https://img.shields.io/badge/license-MIT-green)](LICENSE) [![CI](https://img.shields.io/badge/CI-ready-lightgrey)](https://github.com/nds-stack/bun-otp/actions) [![Tests](https://img.shields.io/badge/tests-35%20pass-brightgreen)](https://github.com/nds-stack/bun-otp)

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

All cryptographic operations use **`Bun.CryptoHasher`** — Bun's native HMAC implementation running directly in C++ (sync, zero-copy, 20× faster than Web Crypto API). No async overhead, no JSC bridge, no external crypto libraries.

### Architecture

```
src/
├── index.ts              → Public API: totp, hotp, generateSecret, generateOTPAuthURI, base32Encode, base32Decode
├── hotp.ts               → HOTP generation & verification (sync)
├── totp.ts               → TOTP generation & verification (sync)
├── otpauth-uri.ts        → OTP Auth URI generation (Google Authenticator format)
├── hotp-core.ts          → Internal: counterToBytes, dynamicTruncation (not public)
├── hmac.ts               → Bun.CryptoHasher HMAC wrapper
├── base32.ts             → RFC 4648 base32 encoder/decoder
├── generate-secret.ts    → CSPRNG secret generation via crypto.getRandomValues()
└── timing-safe-equal.ts  → Constant-time string comparison
```

All functions are **synchronous** — every OTP operation completes in the same tick. No `await` needed.

---

## API

### `generateSecret(length?: number): string`

Generates cryptographically random bytes (`crypto.getRandomValues()`) and returns them as a base32-encoded string.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `length` | `number` | `20` | Number of random bytes (20 bytes → 32 base32 chars) |

- **Returns:** `string` — base32-encoded secret (RFC 4648)
- **Throws:** `RangeError` if `length` is not a positive integer

```typescript
const secret = generateSecret();       // 32 base32 chars (20 bytes)
const secret = generateSecret(32);      // 52 base32 chars (32 bytes)
```

---

### `totp(options: TOTPOptions): string`

Generates a time-based one-time password. Sync — no `await` needed.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `secret` | `string` | (required) | Base32-encoded secret |
| `period` | `number` | `30` | Time step in seconds (must be ≥ 1) |
| `digits` | `number` | `6` | Number of OTP digits (1-10) |
| `algorithm` | `'SHA1' \| 'SHA256' \| 'SHA512'` | `'SHA1'` | HMAC hash algorithm |
| `timestamp` | `number` | `Date.now()` | Custom timestamp in milliseconds |

- **Returns:** `string` — OTP token (zero-padded to `digits`)
- **Throws:** `RangeError` on invalid input

```typescript
const token = totp({ secret, timestamp: Date.now() });
const token = totp({ secret, digits: 8, algorithm: 'SHA256' });
```

---

### `totp.verify(options: TOTPVerifyOptions): boolean`

Verifies a TOTP token. Accepts all `TOTPOptions` plus:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `token` | `string` | (required) | The token to verify |
| `window` | `number` | `0` | Verification window (periods before/after, max ±10) |

- **Returns:** `boolean` — `true` if token is valid for any counter in `[counter - window, counter + window]`
- **Throws:** `RangeError` on invalid input or window > 10

```typescript
const valid = totp.verify({ secret, token: '123456', window: 1 });
```

---

### `hotp(options: HOTPOptions): string`

Generates an HMAC-based one-time password. Sync — no `await` needed.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `secret` | `string` | (required) | Base32-encoded secret |
| `counter` | `number` | (required) | Counter value (non-negative integer) |
| `digits` | `number` | `6` | Number of OTP digits (1-10) |
| `algorithm` | `'SHA1' \| 'SHA256' \| 'SHA512'` | `'SHA1'` | HMAC hash algorithm |

- **Returns:** `string` — OTP token (zero-padded to `digits`)
- **Throws:** `RangeError` on invalid input

```typescript
const token = hotp({ secret, counter: 0 });
const token = hotp({ secret, counter: 42, digits: 8 });
```

---

### `hotp.verify(options: HOTPVerifyOptions): boolean`

Verifies an HOTP token. Accepts all `HOTPOptions` plus:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `token` | `string` | (required) | The token to verify |
| `window` | `number` | `0` | Look-ahead window (counters ahead to check, max 50) |

- **Returns:** `boolean` — `true` if token matches any counter in `[counter, counter + window]`
- **Throws:** `RangeError` on invalid input or window > 50

> **Note:** HOTP verify is forward-only per RFC 4226. Use `window` to tolerate minor counter drift between client and server.

```typescript
const valid = hotp.verify({ secret, counter: 95, token: '123456', window: 10 });
```

---

### `base32Encode(data: Uint8Array): string`

Encodes raw bytes to a base32 string (RFC 4648 with padding).

```typescript
const encoded = base32Encode(new Uint8Array([0, 1, 2]));
// → 'AAAQE======'
```

---

### `base32Decode(str: string): Uint8Array`

Decodes a base32 string (RFC 4648) to raw bytes. Strips whitespace and hyphens automatically. Accepts padding characters (`=`) correctly.

```typescript
const bytes = base32Decode('JBSWY3DPEHPK3PXP');
// → Uint8Array(10)
```

- **Throws:** `Error` if input contains invalid base32 characters or is empty

---

## Error Handling

| Function | Condition | Behavior |
|----------|-----------|----------|
| `generateSecret` | `length` not a positive integer | `RangeError` |
| `totp` / `hotp` | `secret` is empty or invalid base32 | `Error` |
| `totp` / `hotp` | `digits` not 1-10 | `RangeError` |
| `totp` / `hotp` | `counter` negative or > `Number.MAX_SAFE_INTEGER` | `RangeError` |
| `totp` | `period < 1` | `RangeError` |
| `totp` | `timestamp` invalid (NaN, negative) | `RangeError` |
| `totp.verify` / `hotp.verify` | `window > max` (TOTP: 10, HOTP: 50) | `RangeError` |
| `totp.verify` / `hotp.verify` | Token mismatch | Returns `false` |
| `base32Decode` | Empty input or invalid characters | `Error` |
| `base32Decode` | Input exceeds 1,000,000 characters | `RangeError` |

All operations are synchronous. No Promise rejection — every error is thrown immediately.

---

## Limitations

- **Clock dependency** — TOTP requires accurate system time. Use `window` parameter (±10 periods) to tolerate clock skew.
- **Base32 only** — Secrets must be base32-encoded (RFC 4648). Hex or raw bytes are not supported directly. Use `base32Encode()` to convert raw bytes.
- **Bun-only** — Requires `Bun.CryptoHasher` (Bun ≥ 1.3.0). Not compatible with Node.js or Deno.
- **Digits 1-10** — The `digits` parameter is validated to 1-10. This covers all standard OTP configurations (Google Authenticator: 6, Steam: 5, some enterprise: 8).
- **HOTP counter** — Must be a safe integer (`≤ Number.MAX_SAFE_INTEGER`). Practical limit for any real-world usage.

---

## Multi-Instance / Cross-Boundary

TOTP and HOTP are inherently stateless — the only shared state is the secret. You can verify tokens on any instance without coordination:

- **Horizontal scaling** — Each instance verifies independently using the same shared secret (stored in env / secrets manager).
- **HOTP state** — Unlike TOTP, HOTP requires tracking the last successful counter to prevent replay attacks. Use a distributed counter (e.g., Redis) or store per-user state in a database.
- **TOTP drift** — Use `window` to compensate for clock drift between client and server. A window of 1 (±30s) covers most clock skew scenarios.

```typescript
// HOTP counter persistence pattern (Redis)
const counter = await redis.get(`hotp:${userId}`);
const valid = hotp.verify({ secret, counter, token, window: 10 });
if (valid) {
  await redis.set(`hotp:${userId}`, counter + 10); // sync counter
}
```

---

## Migration Guide

### From speakeasy

| speakeasy (sync) | bun-otp (sync) |
|------------------|----------------|
| `speakeasy.totp({ secret, encoding: 'base32' })` | `totp({ secret })` |
| `speakeasy.totp({ secret, encoding: 'base32', algorithm: 'sha256' })` | `totp({ secret, algorithm: 'SHA256' })` |
| `speakeasy.hotp({ secret, counter, encoding: 'base32' })` | `hotp({ secret, counter })` |
| `speakeasy.totp.verify({ secret, token, encoding: 'base32', window: 2 })` | `totp.verify({ secret, token, window: 2 })` |
| `speakeasy.generateSecret().base32` | `generateSecret()` |

**Key differences:**
- No `encoding: 'base32'` — bun-otp expects base32 directly
- Algorithms are uppercase (`SHA256` vs `sha256`)
- All functions are sync (same as speakeasy)
- Zero dependencies vs speakeasy's ~8

### From otplib

| otplib (async) | bun-otp (sync) |
|----------------|----------------|
| `await authenticator.generate(secret)` | `totp({ secret })` |
| `await authenticator.check(token, secret)` | `totp.verify({ secret, token })` |
| `await totp.generate(secret)` | `totp({ secret })` |
| `await hotp.generate(secret, counter)` | `hotp({ secret, counter })` |

**Key differences:**
- No `await` needed — bun-otp is fully synchronous
- No `.generate()`/`.check()` — use direct function calls
- Secret passed as object, not positional
- Zero dependencies vs otplib's ~3

---

## Authenticator App Integration

### Step-by-step enrollment flow

```typescript
import { generateSecret, totp, generateOTPAuthURI, base32Encode } from '@nds-stack/bun-otp';

// 1. Generate a secret for the user
const secret = generateSecret();

// 2. Store the secret in your database
db.users.update(userId, { totpSecret: secret });

// 3. Create an OTP Auth URI for QR code
const uri = generateOTPAuthURI({
  type: 'totp',
  secret,
  issuer: 'MyApp',
  accountName: user.email,
});

// 4. Generate QR code (any QR library)
// npm install qrcode
// import QRCode from 'qrcode';
// const qrImage = await QRCode.toDataURL(uri);
// Display qrImage to user (HTML: <img src={qrImage} />)

// 5. Verify first token to confirm enrollment
const firstToken = promptUser('Enter the code from your authenticator app:');
if (totp.verify({ secret, token: firstToken, window: 2 })) {
  // ✅ Enrollment confirmed
} else {
  // ❌ Wrong code — ask user to try again
}
```

### Supported authenticator apps

| App | Platform | OTP URI support |
|-----|----------|:---------------:|
| Google Authenticator | iOS, Android | ✅ |
| Authy | iOS, Android, Desktop | ✅ |
| Microsoft Authenticator | iOS, Android | ✅ |
| 1Password | iOS, Android, Desktop | ✅ |
| Bitwarden | iOS, Android, Desktop | ✅ |

---

## Customization Guide

### Custom digits
```typescript
const token = totp({ secret, digits: 8 });
```

### Custom algorithm
```typescript
const token = totp({ secret, algorithm: 'SHA256' });
const token = totp({ secret, algorithm: 'SHA512' });
```

### Custom period
```typescript
const token = totp({ secret, period: 60 });
```

### Verification with tolerance
```typescript
const ok = totp.verify({ secret, token, window: 2 });
```

### Extending with custom encoding
```typescript
function hexToBase32(hex: string): string {
  const bytes = new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
  return base32Encode(bytes);
}
const secret = hexToBase32('12345678901234567890abcdef');
const token = totp({ secret });
```

---

### `generateOTPAuthURI(options: OTPAuthURIOptions): string`

Generates an `otpauth://` URI per the [Google Authenticator Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format). Use this to generate QR codes for authenticator app enrollment.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `type` | `'totp' \| 'hotp'` | (required) | OTP type |
| `secret` | `string` | (required) | Base32-encoded secret |
| `issuer` | `string` | (required) | Provider or service name |
| `accountName` | `string` | (required) | User account identifier (email, username) |
| `algorithm` | `'SHA1' \| 'SHA256' \| 'SHA512'` | `'SHA1'` | HMAC algorithm (omitted if SHA1) |
| `digits` | `number` | `6` | OTP digits (omitted if 6) |
| `period` | `number` | `30` | Time step in seconds (TOTP only, omitted if 30) |
| `counter` | `number` | (required for HOTP) | Initial counter value |

- **Returns:** `string` — `otpauth://totp/...` URI

```typescript
const uri = generateOTPAuthURI({
  type: 'totp',
  secret: 'JBSWY3DPEHPK3PXP',
  issuer: 'MyApp',
  accountName: 'user@example.com',
});
// → otpauth://totp/MyApp:user%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp
```

---

### `generateQRCodeURL(uri: string, size?: number): string`

Generates a URL to a QR code API (qrserver.com) for any OTP Auth URI. Use this to generate QR codes for authenticator app enrollment.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `uri` | `string` | (required) | OTP Auth URI from `generateOTPAuthURI()` |
| `size` | `number` | `200` | QR code size in pixels |

- **Returns:** `string` — URL to QR code image

```typescript
const uri = generateOTPAuthURI({ type: 'totp', secret, issuer: 'MyApp', accountName: 'user@example.com' });
const qr = generateQRCodeURL(uri, 300);
// → https://api.qrserver.com/v1/create-qr-code/?data=otpauth%3A%2F%2F...&size=300x300
```

---

### `steamTotp(key: Uint8Array, timestamp: number, algorithm?): string`

Generates a Steam Guard–style one-time password (5 characters, custom alphabet `23456789BCDFGHJKMNPQRTVWXY`).

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `key` | `Uint8Array` | (required) | Raw bytes (NOT base32). Use `base32Decode(secret)` first |
| `timestamp` | `number` | (required) | Unix timestamp in milliseconds |
| `algorithm` | `'SHA1' \| 'SHA256' \| 'SHA512'` | `'SHA1'` | HMAC hash algorithm |

- **Returns:** `string` — 5-character Steam Guard code

```typescript
const key = base32Decode(secret);
const code = steamTotp(key, Date.now());
// → '2B3C7' (5-char alphanumeric)
```

### Notes on sync API
All functions are sync via `Bun.CryptoHasher`. Unlike TOTP libraries built on Web Crypto (which return Promises), `bun-otp` operations complete immediately. This means:
- No `await` needed anywhere
- Works in `Array.map()`, computed properties, and other sync contexts
- ~7× faster than Web Crypto–based alternatives under load

---

## Comparison Table

| Feature | `@nds-stack/bun-otp` | `speakeasy` | `otplib` | `@epic-web/totp` |
|---------|---------------------|-------------|----------|:-----------------:|
| Dependencies | **Zero** | ~8 (crypto-js, etc.) | ~3 (thirty-two, etc.) | 2 |
| Runtime | **Bun** (CryptoHasher) | Node.js | Node.js/universal | Bun/Node/Browser |
| TypeScript | **First-class** | Community types | Built-in | Partial (untyped) |
| Bundle size | **~6 KB** | ~50 KB | ~30 KB | ~5 KB |
| Algorithms | SHA1/256/512 | SHA1/256/512 | SHA1/256/512 | SHA1/256/512 |
| API style | **Sync** (no await) | **Sync** | Sync/Async | Async |
| Base32 | Custom RFC 4648 | npm (thirty-two) | npm (thirty-two) | npm (base32-decode) |
| Steam TOTP | ✅ Built-in | ❌ No | ❌ No | ❌ No |
| QR code URL | ✅ Built-in | ❌ No | ❌ No | ❌ No |
| HOTP | ✅ Full support | ✅ Full support | ✅ Full support | ❌ TOTP only |
| OTP URI | ✅ Implemented | ✅ Built-in | ✅ Built-in | ✅ Built-in |

---

## Benchmarks

### Methodology
- Each operation: average of **5 runs × 1000 iterations**
- Warmup: 100 iterations before measurement
- Sync libraries: measured with tight loop (no `await`)
- Async libraries: measured with `await` per iteration
- Hardware: Bun 1.3.14 (Windows 11, AMD Ryzen 7)

### Results (ops/s — higher is better)

| Operation | `bun-otp` | `speakeasy` | `otplib` | `@epic-web/totp` | `otpauth` |
|-----------|:---------:|:-----------:|:--------:|:----------------:|:---------:|
| TOTP SHA1 | **196K** 🏆 | 117K | 44K | 19K | 92K |
| TOTP SHA256 | **179K** 🏆 | 97K | 38K | 20K | 62K |
| TOTP verify | **160K** 🏆 | N/A | — | 9K | N/A |
| HOTP SHA1 | **265K** 🏆 | 137K | 57K | N/A | — |
| Base32 encode | **209K** 🏆 | N/A | N/A | N/A | N/A |
| Base32 decode | **123K** 🏆 | N/A | N/A | N/A | N/A |

*`otplib` marked as "—" due to API changes in v13. Run `bun test ./bench/otp.bench.ts` on your hardware.*

`bun-otp` is the fastest OTP library on Bun thanks to `Bun.CryptoHasher` (native C++ HMAC, no JS bridge overhead).

To reproduce: `bun install && bun test ./bench/otp.bench.ts`

---

## Real-World Example

### TOTP 2FA for a web application

```typescript
import { generateSecret, totp, base32Encode } from '@nds-stack/bun-otp';

// ── Enrollment ──────────────────────────────────────
// Called once when user enables 2FA
function enrollUser(userId: string) {
  const secret = generateSecret();

  // Store secret in database (associated with user)
  db.users.update(userId, { totpSecret: secret });

  // Return secret for QR code generation
  return { secret };
}

// ── Verification ────────────────────────────────────
// Called every time user logs in
function verify2FA(userId: string, userCode: string): boolean {
  const user = db.users.get(userId);
  if (!user.totpSecret) throw new Error('2FA not enrolled');

  return totp.verify({
    secret: user.totpSecret,
    token: userCode,
    window: 1, // tolerate ±30s clock drift
  });
}

// ── Usage ───────────────────────────────────────────
const { secret } = enrollUser('user-123');
// Send `secret` to authenticator app:
// otpauth://totp/MyApp:user@example.com?secret=...

const isValid = verify2FA('user-123', '428936');
console.log(isValid ? '✅ Access granted' : '❌ Invalid code');
```

### HOTP with counter persistence

```typescript
import { hotp, generateSecret } from '@nds-stack/bun-otp';

let serverCounter = 0;

function generateCode(): string {
  const token = hotp({ secret: process.env.HOTP_SECRET!, counter: serverCounter });
  serverCounter++; // increment after each generation
  return token;
}

function verifyCode(token: string): boolean {
  const valid = hotp.verify({
    secret: process.env.HOTP_SECRET!,
    counter: serverCounter,
    token,
    window: 10,
  });
  if (valid) serverCounter++; // sync counter
  return valid;
}
```
