# Changelog

## [0.1.0-alpha.4] — 2026-05-26

### Added
- `generateOTPAuthURI()` — OTP Auth URI generation (Google Authenticator Key Uri Format)
- Migration guide from speakeasy/otplib (in README)
- Authenticator app integration guide (in README)
- Full README rewrite for context7 AI indexing — 9 sections with architecture, all API docs, error table, multi-instance patterns, production examples
- Benchmark: 5-run average with min/max reporting
- Base32 decode: max input length guard (1M chars)
- Base32 decode: pre-allocated Uint8Array (no intermediate array)
- HOTP verify: counter validation (was missing)
- `.gitignore`: `bench/Competitor/` entry

### Changed
- `hotp()` / `totp()` — sync API (no async/await, no Promise wrapping)
- `hotpCore` moved to `src/hotp-core.ts` (internal, not exported)
- Counter overflow fix: BigInt in `counterToBytes`
- Improved `hotp` validation: merge redundant checks

### Fixed
- Benchmark: sync/async detection restored (was not awaiting Promises)
- README: stale Web Crypto docs → Bun.CryptoHasher
- Benchmark: warmup iterations added

## [0.1.0-alpha.3] — 2026-05-26

### Changed
- Web Crypto (`crypto.subtle`) → **`Bun.CryptoHasher`** (sync native, 20× faster)
- `counterToBytes` using BigInt → plain number arithmetic
- Redundant input validation in `hotpCore` (validated once in `hotpFn`)
- `Math.pow(10, digits)` → `10 ** digits` (ES2021)

### Fixed
- Benchmark methodology: sync libs measured without `await` overhead
- README benchmark table with honest latency vs throughput comparison

## [0.1.0-alpha.2] — 2026-05-26

### Added
- Competitor benchmarks (`speakeasy`, `otplib`) in benchmark suite
- `hotp.core()` — internal function exposed for optimized batch generation

### Fixed
- Bench script broken (`bun run bench` → `bun test ./bench/otp.bench.ts`)
- Inconsistent `.js` imports in `src/index.ts`
- TOTP verify redundant base32 decode per window iteration (decode once now)
- README benchmark table updated with real measured numbers

## [0.1.0-alpha.1] — 2026-05-26

### Added
- TOTP (RFC 6238) with SHA1/SHA256/SHA512, configurable digits/period
- HOTP (RFC 4226) with dynamic truncation and configurable window
- Base32 encode/decode (RFC 4648) — custom implementation, zero deps
- Cryptographically secure secret generation via `crypto.getRandomValues()`
- Verification with configurable tolerance windows
- Full TypeScript types and strict mode
- Input validation: digits range (1-10), counter (≥0), timestamp, empty/padding-only base32
- Constant-time token comparison (`timingSafeEqual`)
- Window validation with max limits (TOTP: 10, HOTP: 50)
- RFC 4226 known-value test vectors (29 tests total)
- Clean script (`rm -rf dist`) for build hygiene
- Performance benchmarks with native Web Crypto baseline
- Comprehensive error-path tests

### Fixed
- `totp.verify()` crash on negative counter when `timestamp=0` with `window>0`
- Type declarations not emitted (`tsconfig.build.json` missing `noEmit: false`)
- Redundant base32 decode in verify loops (decode once, reuse)
- Stale `dist/src/` artifacts from old build config
- File naming violation (`generateSecret.ts` → `generate-secret.ts`)
- `hotpCore` leaking to public API
- `ALGORITHM_MAP` type safety (`Record<string, string>` → `Record<AlgorithmName, string>`)
- Bundle size: 6.37 KB (uncompressed), zero dependencies
