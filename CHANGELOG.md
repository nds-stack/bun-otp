# Changelog

## [0.1.0-alpha.0] — 2026-05-26
### Added
- TOTP (RFC 6238) with SHA1/SHA256/SHA512, configurable digits/period
- HOTP (RFC 4226) with dynamic truncation and configurable window
- Base32 encode/decode (RFC 4648) — custom implementation, zero deps
- Cryptographically secure secret generation via `crypto.getRandomValues()`
- Verification with configurable tolerance windows
- Full TypeScript types and strict mode
- Comprehensive test suite (17 tests)
- Performance benchmarks
