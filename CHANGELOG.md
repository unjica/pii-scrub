# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-29

### Added

- `scrubText`, `scrub`, `scrubError` and `createScrubber` with configurable built-in detectors, custom detectors, custom placeholders and sensitive object keys.
- Text detectors for emails, bearer tokens, `Authorization` headers, common API key formats, IBAN (mod-97), card numbers (Luhn + IIN), phone numbers, JWTs, URL credentials and query secrets, cookies, JSON secrets and optional IPv4/IPv6.
- Structure-aware scrubbing of objects, arrays, `Map`, `Set` and `Error` (including `cause` and `AggregateError`), with circular-reference protection and `maxDepth`/`maxNodes` limits.
- ESM and CommonJS builds with TypeScript types; no runtime dependencies.
- False-positive, fuzz and ReDoS test suites.

### Notes

- The free-text `bearer` detector intentionally ignores short, letters-only values (for example `Bearer token` in prose) to reduce false positives. Full `Authorization:` header lines and `authorization` object keys are still always redacted. See "Limitations" in the README.

[0.1.0]: https://github.com/unjica/pii-scrub/releases/tag/v0.1.0
