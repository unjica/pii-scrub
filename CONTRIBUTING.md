# Contributing

Bug reports and false-positive/false-negative examples are very welcome — please include a minimal input string and the expected output (use fake data only).

- `npm ci && npm run lint && npm run typecheck && npm test && npm run build`
- New or changed detectors need tests in `test/false-positives.test.ts` and `test/redos.test.ts`.
- No runtime dependencies. New features are added only for a concrete use case.
- Versioning follows semver; see `CHANGELOG.md`.
