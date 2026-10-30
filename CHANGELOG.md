# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-10-30

### Fixed

- Stripe-style keys (`sk_`/`pk_`/`rk_` + `live_`/`test_`) and webhook secrets (`whsec_`) with a short body (8–15 characters, e.g. `sk_live_abc123XYZ456`) were not redacted because the detector required at least 16 characters after the prefix. The minimum is now 8; the prefix must still start at a word boundary, so identifiers like `task_live_status` are kept.

### Notes

- Vendor formats with a fixed or documented minimum length (GitHub `ghp_` 36, npm `npm_` 36, AWS 16, Google `AIza` 35, GitLab `glpat-` 20) and the generic `sk-`/`pk-` (16+) are unchanged: shorter strings are not valid tokens of those vendors and lowering the limits would add false positives.

## [0.1.0] - 2026-10-29

### Added

- `scrubText`, `scrub`, `scrubError` and `createScrubber` with configurable built-in detectors, custom detectors, custom placeholders and sensitive object keys.
- Text detectors for emails, bearer tokens, `Authorization` headers, common API key formats, IBAN (mod-97), card numbers (Luhn + IIN), phone numbers, JWTs, URL credentials and query secrets, cookies, JSON secrets and optional IPv4/IPv6.
- Structure-aware scrubbing of objects, arrays, `Map`, `Set` and `Error` (including `cause` and `AggregateError`), with circular-reference protection and `maxDepth`/`maxNodes` limits.
- ESM and CommonJS builds with TypeScript types; no runtime dependencies.
- False-positive, fuzz and ReDoS test suites.

### Notes

- The free-text `bearer` detector intentionally ignores short, letters-only values (for example `Bearer token` in prose) to reduce false positives. Full `Authorization:` header lines and `authorization` object keys are still always redacted. See "Limitations" in the README.

[0.1.1]: https://github.com/unjica/pii-scrub/releases/tag/v0.1.1
[0.1.0]: https://github.com/unjica/pii-scrub/releases/tag/v0.1.0
