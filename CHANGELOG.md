# Changelog

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
- RFC 4226 known-value test vectors (24 tests total)
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
