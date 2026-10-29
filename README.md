# @tacko/pii-scrub

Zero-dependency, best-effort scrubbing of personal data and secrets from **logs, telemetry payloads and `Error` objects**.

- **Typed placeholders** (`[email]`, `[card]`, `[api-key]`, …) instead of a generic `[REDACTED]`, so scrubbed logs stay debuggable.
- **Low false-positive bias**: Luhn-validated card numbers, IBAN checksums, no bare-digit phone matching, versions, timestamps, hashes and trace IDs are left alone.
- **Text, deep objects and Errors**: strings, arrays, plain objects, `Map`, `Set` and `Error` (message, stack, `cause`, own properties). The input is never mutated.
- **Safe on untrusted input**: circular-reference protection, depth and node limits, linear-time regexes (ReDoS-tested), `__proto__`-safe output.
- **Configurable**: enable/disable detectors, add custom detectors, change placeholders, add sensitive key names.
- ESM + CommonJS, TypeScript types, Node 18+, also runs in browsers and edge runtimes (uses only ES2018+ built-ins).

> **This is not a compliance tool.** It is pattern-based, best-effort redaction. It does **not** make your logs GDPR/HIPAA/PCI compliant and it does not guarantee that no personal data remains. Read [Limitations](#limitations).

## Install

```sh
npm install @tacko/pii-scrub
```

## Quick start

```ts
import { scrubText, scrub, scrubError } from "@tacko/pii-scrub";

scrubText("Payment failed for jane@example.com, card 4111 1111 1111 1111");
// → "Payment failed for [email], card [card]"

scrub({
  user: { email: "jane@example.com", plan: "pro" },
  headers: { authorization: "Bearer eyJhbGciOi...", accept: "application/json" },
  note: "retry with token=abc123",
});
// → {
//     user: { email: "[email]", plan: "pro" },
//     headers: { authorization: "[bearer-token]", accept: "application/json" },
//     note: "retry with token=[redacted]",
//   }

const safe = scrubError(new Error("lookup failed for jane@example.com"));
safe instanceof Error; // true, same prototype as the input
safe.message; // "lookup failed for [email]"
safe.stack; // stack with the message scrubbed, frames and newlines intact
```

For repeated use (e.g. in a logger hook), create a scrubber once:

```ts
import { createScrubber } from "@tacko/pii-scrub";

const scrubber = createScrubber({
  detectors: { ipv4: true, ipv6: true, urlQuery: false },
  sensitiveKeys: ["customer_id", "national_id"],
  customDetectors: [{ name: "orderRef", pattern: /\bORD-\d{8}\b/g, replacement: "[order]" }],
  placeholders: { email: "<email>" },
});

scrubber.text("...");
scrubber.value(payload);
scrubber.error(err);
```

## Before / after

| Input                                                                    | Output                                   |
| ------------------------------------------------------------------------ | ---------------------------------------- |
| `Failed for user@example.com`                                            | `Failed for [email]`                     |
| `Token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature`                   | `Token [token]`                          |
| `Authorization: Bearer abc.def-123`                                      | `Authorization: [bearer-token]`          |
| `key sk-proj-Ab3dEf6hIj9kLmNoPq`                                         | `key [api-key]`                          |
| `card 4111 1111 1111 1111 charged`                                       | `card [card] charged`                    |
| `pay DE89 3704 0044 0532 0130 00`                                        | `pay [iban]`                             |
| `call +386 40 123 456`                                                   | `call [phone]`                           |
| `GET https://api.example.com/orders?id=123#top`                          | `GET https://api.example.com/orders#top` |
| `GET https://api.example.com/cb?access_token=abc`                        | `GET https://api.example.com/cb`         |
| `{"password":"hunter2"}` (inside a string)                               | `{"password":"[redacted]"}`              |
| `user_id=a0000000-0000-4000-8000-000000000001`                           | `user_id=[id:1]`                         |
| `v1.2.3`, `2026-10-29T19:01:41Z`, `order 5551234567`, `trace b0000000-…` | unchanged                                |

## API

### `scrubText(text, options?) → string`

Scrubs free-form text with the text detectors. Newlines and other whitespace are preserved, so stack traces stay readable. Non-string input is returned unchanged.

### `scrub(value, options?) → value`

Deep-scrubs any value and returns a new value; the input is never mutated.

- **strings** → `scrubText`
- **object keys** in the sensitive key list (see below) → the value is replaced by the key's placeholder, whatever its type (`null`/`undefined` are kept)
- **arrays, plain objects, class instances** → walked; class instances become plain objects with their own enumerable properties
- **`Error`** → see `scrubError`
- **`Map`** → new `Map`; string keys are checked against the sensitive key list, values are walked
- **`Set`** → new `Set` of walked values
- **`Date`** → copied; `RegExp`, typed arrays, `ArrayBuffer`/`Buffer` → returned as is (binary data is not inspected)
- **numbers, booleans, bigint, symbols, functions** → unchanged
- **circular references** → `"[circular]"`; shared (non-circular) references stay shared in the output
- **limits**: containers deeper than `maxDepth` (default 32) or visited after `maxNodes` (default 10 000) nodes become `"[truncated]"`. Strings are always scrubbed, never passed through raw.

### `scrubError(error, options?) → Error`

Returns a new object with the same prototype (`instanceof` still works) in which `message`, `stack`, `cause`, `errors` (for `AggregateError`) and all other own properties are scrubbed. Property enumerability is preserved. Non-Error input is handled like `scrub`.

### `createScrubber(options?) → { text, value, error }`

Compiles options once. Prefer this when scrubbing in a hot path with custom options.

### Options

| Option                 | Default                                                              | Description                                                                                                                                                                                                                  |
| ---------------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `detectors`            | all on except `ipv4`, `ipv6`                                         | `{ [name]: boolean }` to enable/disable built-in text detectors. Unknown names throw.                                                                                                                                        |
| `customDetectors`      | `[]`                                                                 | `{ name, pattern, replacement?, validate? }[]`. Run **before** the built-ins, in order. `g` flag is added automatically. `replacement` is a literal string (no `$1` expansion) or `(match) => string`; default `[redacted]`. |
| `placeholders`         | see below                                                            | Override any placeholder string. `id` may contain `{n}`.                                                                                                                                                                     |
| `sensitiveKeys`        | `[]`                                                                 | Extra object keys. Array → `[redacted]` (built-in keys keep their typed placeholder). Record `{ key: placeholder }` → explicit placeholder (overrides built-ins).                                                            |
| `defaultSensitiveKeys` | `true`                                                               | Set `false` to drop the built-in key list.                                                                                                                                                                                   |
| `secretNames`          | see below                                                            | Names used by `queryParam`, `keyValue`, `jsonSecret` and `urlQuery`. Replaces the default list.                                                                                                                              |
| `contextIdNames`       | `user_id`, `anonymous_id`, `session_id`, `customer_id`, `account_id` | Keys whose UUID value becomes a correlation id.                                                                                                                                                                              |
| `maxDepth`             | `32`                                                                 | Max container nesting.                                                                                                                                                                                                       |
| `maxNodes`             | `10000`                                                              | Max visited nodes per call.                                                                                                                                                                                                  |

Keys are compared case-insensitively with non-alphanumerics removed, so `api_key`, `apiKey` and `API-KEY` are the same key.

### Built-in text detectors (in run order)

| Name                  | Default | Matches                                                                                                                                                                                                               | Placeholder                     |
| --------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `email`               | on      | `local@domain.tld` (local ≤ 64, domain ≤ 253 chars)                                                                                                                                                                   | `[email]`                       |
| `jwt`                 | on      | `eyJ….….…` three base64url segments                                                                                                                                                                                   | `[token]`                       |
| `bearer`              | on      | `Bearer <token>` where the token has a digit/punctuation or is ≥ 20 chars (so "missing Bearer token" is kept)                                                                                                         | `[bearer-token]`                |
| `apiKey`              | on      | `sk-…`/`pk-…` (OpenAI/Anthropic-style), Stripe `sk_/pk_/rk_live_/test_`, `whsec_`, GitHub `ghp_/gho_/ghu_/ghs_/ghr_`, `github_pat_`, GitLab `glpat-`, Slack `xox?-`, AWS `AKIA…`/`ASIA…`, Google `AIza…`, npm `npm_…` | `[api-key]`                     |
| `iban`                | on      | Upper-case IBANs, compact or in groups of 4, validated by country length + mod-97                                                                                                                                     | `[iban]`                        |
| `card`                | on      | 13–19 digits (optionally grouped by spaces/dashes), Luhn-valid, starting with 2–6 (13 digits only for 4); UUID segments are ignored                                                                                   | `[card]`                        |
| `phone`               | on      | `+` followed by 7–15 digits (spaces/dashes allowed); NANP with separators `(555) 123-4567`, `555-123-4567`. Bare digit runs and dotted numbers are **not** matched.                                                   | `[phone]`                       |
| `ipv6`                | **off** | Valid IPv6 incl. `::` compression and embedded IPv4 (`::1`, `a::b` are skipped)                                                                                                                                       | `[ip]`                          |
| `ipv4`                | **off** | Valid dotted quads (`0–255`, not preceded by a letter, e.g. `v1.2.3.4` is kept)                                                                                                                                       | `[ip]`                          |
| `queryParam`          | on      | `?name=value` / `&name=value` for secret names                                                                                                                                                                        | `?name=[redacted]`              |
| `keyValue`            | on      | `name=value` for secret names                                                                                                                                                                                         | `name=[redacted]`               |
| `jsonSecret`          | on      | `"name": "value"` inside serialized JSON for secret names                                                                                                                                                             | `"name": "[redacted]"`          |
| `cookieHeader`        | on      | `Cookie:` / `Set-Cookie:` header lines                                                                                                                                                                                | `Cookie: [cookie]`              |
| `authorizationHeader` | on      | `Authorization:` header lines (any scheme)                                                                                                                                                                            | `Authorization: [bearer-token]` |
| `urlQuery`            | on      | Query strings of `http(s)://` URLs are removed; the `#fragment` is kept unless the query contains a secret name or `key=`                                                                                             | —                               |
| `contextId`           | on      | UUIDs after `user_id=`, `session-id:` etc. Same UUID → same id within one call                                                                                                                                        | `user_id=[id:1]`                |

Default `secretNames`: `password`, `passwd`, `secret`, `client_secret`, `token`, `access_token`, `refresh_token`, `id_token`, `api_key`, `auth`, `session`, `cookie` (`_`/`-` in a name also match the other separator or none).

Built-in sensitive object keys (normalized): `email`, `emailaddress`, `useremail`, `mail` → `[email]`; `phone`, `phonenumber`, `mobile`, `cellphone` → `[phone]`; `ssn` → `[ssn]`; `password`, `passwd` → `[password]`; `secret`, `clientsecret`, `privatekey` → `[secret]`; `token`, `accesstoken`, `refreshtoken`, `idtoken`, `auth` → `[token]`; `apikey`, `apisecret` → `[api-key]`; `authorization` → `[bearer-token]`; `cookie`, `setcookie` → `[cookie]`; `creditcard`, `cardnumber`, `cvv`, `cvc` → `[card]`; `iban` → `[iban]`.

Also exported: `passesLuhn`, `isValidIban`, `isValidIpv4`, `isValidIpv6`, `BUILT_IN_DETECTORS`, `DEFAULT_PLACEHOLDERS`, `DEFAULT_SENSITIVE_KEYS`, `DEFAULT_SECRET_NAMES`, `DEFAULT_CONTEXT_ID_NAMES`.

## Recipes

**pino** – scrub the whole log object:

```ts
import pino from "pino";
import { createScrubber } from "@tacko/pii-scrub";

const scrubber = createScrubber();
const logger = pino({ formatters: { log: (obj) => scrubber.value(obj) } });
```

**Sentry** – scrub events before they leave the process:

```ts
Sentry.init({ dsn, beforeSend: (event) => scrubber.value(event) });
```

**Express/Fastify error handler** – log a scrubbed copy, keep the original for control flow:

```ts
app.use((err, req, res, next) => {
  logger.error(scrubber.error(err));
  next(err);
});
```

## Limitations

This library is a **best-effort, pattern-based filter**. Treat it as one layer of defence, not as a guarantee.

- **Not a compliance tool.** Using it does not make a system GDPR, CCPA, HIPAA or PCI DSS compliant. You still need data minimisation, access control, retention policies and, where required, a proper DLP solution.
- **No names, addresses or free-form personal data.** It does not detect people's names, postal addresses, dates of birth, gender, health data, usernames, or any personal data that has no fixed format.
- **Only the formats listed above.** Not detected: national ID numbers (SSN/EMŠO/etc.) in free text (only under the `ssn` key), passport and driving-licence numbers, tax/VAT numbers, licence plates, lowercase or unusual IBAN formats, bank account numbers that are not IBANs, card numbers with unusual separators or split across fields, phone numbers without a `+` country code that are not NANP-formatted (e.g. `040 123 456`), API keys of vendors not listed, passwords that appear without a recognisable key name, private keys/PEM blocks, MAC addresses, geolocation, device IDs.
- **IP addresses are off by default** (they are personal data under GDPR, but matching them by default would break version strings like `1.2.3.4`). Enable `ipv4`/`ipv6` if you need them.
- **False positives are possible**, e.g. a 16-digit order number that happens to pass Luhn, `+1500000` read as a phone number, or a NANP-like `123 456 7890`. Placeholders are typed so you can see what happened.
- **False negatives are possible**: secrets glued to other characters (`x4111111111111111`), obfuscated or encoded data (base64, URL-encoded, hex, split across log lines), and values in numeric fields that are not under a sensitive key (numbers are never pattern-matched).
- **Structure-aware only for JS values.** Serialized JSON inside strings is treated as text (`jsonSecret` covers the common `"password": "…"` case). Binary data (`Buffer`, typed arrays) is returned unchanged and not inspected.
- **Class instances lose their prototype** (they become plain objects); `Error`s keep theirs. Getters on plain objects are invoked; a throwing getter becomes `[redacted]`. Symbol-keyed and non-enumerable properties of non-Error objects are dropped.
- **Correlation ids (`[id:n]`) are only stable within one call**, not across calls or processes.
- **Limits truncate data**: very deep or very large payloads are partially replaced by `[truncated]`.
- Custom detectors are your responsibility: avoid nested quantifiers like `(a+)+` to keep them ReDoS-safe.

## Development

```sh
npm ci
npm run lint && npm run typecheck && npm test && npm run build
npm run test:pack   # npm pack + install the tarball in a temp project, check ESM import, CJS require and types
```

The test suite contains unit tests, seeded fuzz tests (`FUZZ_ITERATIONS=20000 npm test` for a longer run), a false-positive corpus and ReDoS timing tests.

## License

MIT © Sanja Malovic
