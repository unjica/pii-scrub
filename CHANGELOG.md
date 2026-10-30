# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.2] - 2026-10-30

### Added

- `onLimit: "scrub"` option (with `hardMaxDepth`, default 128, and `hardMaxNodes`, default 10 000): `maxDepth`/`maxNodes` become soft limits and strings and sensitive keys past them are still scrubbed instead of becoming `"[truncated]"`. The default stays `"truncate"`, so existing behaviour is unchanged.
- `secretHeader` detector: `X-Api-Key:` → `[api-key]` and `X-…-Token:` header lines (e.g. `X-Auth-Token`, `X-Shopify-Access-Token`) → `[token]`.
- `urlCredentials` detector: `scheme://user:pass@host` → `scheme://[redacted]@host` (before, `pass@host` was only caught by accident by the email detector and became `[email]`).
- `aws_secret_access_key` in the default secret names (`aws_secret_access_key=…` → `aws_secret_access_key=[redacted]`).
- ReDoS tests for the 64 KB adversarial inputs from the QA evaluation (each < 50 ms) and a linearity test for the card detector.

### Fixed

- Card detector performance: UUIDs are now looked up only around candidate digit runs with 13+ digits, instead of comparing every digit run with every UUID (O(n×m)). A 5 MB mixed log now takes ~120 ms instead of ~3.3 s; 64 KB `"1 "`/`"1-"` inputs ~3.5 ms instead of ~40 ms.
- Card false positive on short space-separated number groups (`counts 100 200 300 400 500 600 700` was partly turned into `[card]`): in a grouped number every group except the last must have at least 4 digits.
- A card number in the same digit run as a UUID (e.g. `…-000000000001 4111111111111111`) is now redacted; previously the whole run was skipped.
- `urlQuery` only visits tokens that contain a URL (about 10× faster on large logs).

### Changed

- Output for `scheme://user:pass@host` URLs changes from `scheme://user:[email]…` to `scheme://[redacted]@host`. Error fingerprints computed after scrubbing may change for messages that contain URL credentials, `X-Api-Key`/`X-…-Token` headers, `aws_secret_access_key=`, or short space-separated number groups.

### Security (development dependencies only)

- Dev tooling updated to clear all 6 Dependabot alerts (#3): `vitest` 3 → 5 (drops the vulnerable `tinypool`), `esbuild` overridden to `^0.28.1`. These packages are not shipped; the published package still has no runtime dependencies and still supports Node >= 18. Running the test suite now officially needs Node ^22.12 || >=24 (vitest 5).

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

[0.1.2]: https://github.com/unjica/pii-scrub/releases/tag/v0.1.2
[0.1.1]: https://github.com/unjica/pii-scrub/releases/tag/v0.1.1
[0.1.0]: https://github.com/unjica/pii-scrub/releases/tag/v0.1.0
