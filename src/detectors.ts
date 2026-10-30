import type { BuiltInDetectorName, CustomDetector, Placeholders } from "./types.js";
import { ibanLength, isValidIban, isValidIpv4, isValidIpv6, passesLuhn } from "./validators.js";

/** Per-call state shared by all strings scrubbed in one call (e.g. correlation ids). */
export interface ScrubContext {
  ids: Map<string, string>;
}

export interface CompiledDetector {
  name: string;
  apply(text: string, ctx: ScrubContext): string;
}

export interface DetectorConfig {
  placeholders: Placeholders;
  secretNames: readonly string[];
  contextIdNames: readonly string[];
}

export const BUILT_IN_DETECTORS: readonly BuiltInDetectorName[] = [
  "urlCredentials",
  "email",
  "jwt",
  "bearer",
  "apiKey",
  "iban",
  "card",
  "phone",
  "ipv6",
  "ipv4",
  "queryParam",
  "keyValue",
  "jsonSecret",
  "cookieHeader",
  "authorizationHeader",
  "secretHeader",
  "urlQuery",
  "contextId",
];

export const DEFAULT_DISABLED: ReadonlySet<BuiltInDetectorName> = new Set(["ipv4", "ipv6"]);

export const DEFAULT_SECRET_NAMES: readonly string[] = [
  "password",
  "passwd",
  "secret",
  "client_secret",
  "token",
  "access_token",
  "refresh_token",
  "id_token",
  "api_key",
  "aws_secret_access_key",
  "auth",
  "session",
  "cookie",
];

export const DEFAULT_CONTEXT_ID_NAMES: readonly string[] = [
  "user_id",
  "anonymous_id",
  "session_id",
  "customer_id",
  "account_id",
];

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Build a linear alternation from names; `_`/`-` match either separator or none. */
function namesAlternation(names: readonly string[]): string {
  const parts = [...new Set(names.map((n) => n.trim()).filter(Boolean))]
    .sort((a, b) => b.length - a.length)
    .map((n) => escapeRegExp(n).replace(/[_-]/g, "[_-]?"));
  // A pattern that can never match keeps the regex valid when the list is empty.
  return parts.length > 0 ? parts.join("|") : "(?!)";
}

const EMAIL_RE = /\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}\b/gi;
const JWT_RE = /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
// The lookahead skips prose such as "missing Bearer token": a real token has a digit or
// punctuation, or is at least 20 characters long. Spaces/tabs only, so newlines survive.
const BEARER_RE =
  /\bBearer[ \t]+(?=[A-Za-z0-9._~+/=-]*[0-9._~+/=-]|[A-Za-z0-9._~+/=-]{20})[A-Za-z0-9._~+/=-]{4,}\b/gi;
const API_KEY_RE = new RegExp(
  "(?<![A-Za-z0-9_])(?:" +
    [
      "(?:sk|pk)-[A-Za-z0-9_-]{16,}", // OpenAI/Anthropic-style and generic sk-/pk- keys
      "(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}", // Stripe (test/restricted keys can be short)
      "whsec_[A-Za-z0-9]{8,}", // Stripe webhook secret
      "gh[pousr]_[A-Za-z0-9]{36,}", // GitHub tokens
      "github_pat_[A-Za-z0-9_]{22,}", // GitHub fine-grained PAT
      "glpat-[A-Za-z0-9_-]{20,}", // GitLab PAT
      "xox[abposr]-[A-Za-z0-9-]{10,}", // Slack
      "(?:AKIA|ASIA)[0-9A-Z]{16}", // AWS access key id
      "AIza[0-9A-Za-z_-]{35}", // Google API key
      "npm_[A-Za-z0-9]{36}", // npm token
    ].join("|") +
    ")(?![A-Za-z0-9])",
  "g",
);
const IBAN_RE = /(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}(?![A-Za-z0-9])/g;
// A whole run of digit groups separated by 1–3 spaces/dashes with at least 13 digits (cheap
// bounded lookahead); card spans are picked inside it.
const CARD_RE = /(?<![A-Za-z0-9])(?=\d(?:[ -]{0,3}\d){12})\d+(?:[ -]{1,3}\d+)*(?![A-Za-z0-9])/g;
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const PHONE_E164_RE = /(?<![\w])\+[1-9](?:[\s-]*\d){6,14}(?![\d])/g;
const PHONE_NANP_RE = /(?<![\w])(?:\+?1[\s-]?)?\(?\d{3}\)?[\s-]\d{3}[\s-]\d{4}(?![\d])/g;
const IPV4_RE = /(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?!\w|\.\d)/g;
const IPV6_RE = /(?<![\w:.])[0-9A-Fa-f:.]{2,45}(?![\w:.])/g;
const COOKIE_HEADER_RE = /\b(cookie|set-cookie)[ \t]*:[ \t]*[^\r\n]+/gi;
const AUTHORIZATION_HEADER_RE = /\b(authorization)[ \t]*:[ \t]*[^\r\n]+/gi;
// `X-Api-Key:` and `X-…-Token:` header lines (at most 4 extra name segments keeps it linear).
const SECRET_HEADER_RE = /\b(x-api-key|x-(?:[a-z0-9]+-){0,4}token)[ \t]*:[ \t]*[^\s'"]+/gi;
// `scheme://user:pass@host`: only the user-info part is replaced, the scheme and host are kept.
const URL_CREDENTIALS_RE = /:\/\/[^\s/?#@:]+:[^\s/?#@]*@/g;
const URL_START_RE = /https?:\/\//gi;
const SPACE_RE = /\s/g;

function isLikelyCardNumber(digits: string): boolean {
  if (!passesLuhn(digits)) return false;
  // Major networks (Visa, Mastercard, Amex, Discover, JCB, Diners, UnionPay, Maestro) start with 2–6.
  // This keeps epoch-millisecond timestamps (17…/18…) and similar IDs intact.
  const first = digits.charCodeAt(0) - 48;
  if (first < 2 || first > 6) return false;
  // 13-digit PANs only exist for legacy Visa.
  if (digits.length === 13 && first !== 4) return false;
  return true;
}

/**
 * Find card numbers inside a run of digit groups such as "9 4111 1111 1111 1111 7".
 * Spans always cover whole groups and 13–19 digits; the longest valid span wins, left to right.
 * In a span of several groups, every group except the last has at least 4 digits.
 * Work is bounded: at most 19 groups are combined per starting group.
 */
function replaceCardSpans(match: string, placeholder: string): string {
  const groups: Array<{ start: number; end: number; len: number }> = [];
  for (const g of match.matchAll(/\d+/g)) {
    const start = g.index ?? 0;
    groups.push({ start, end: start + g[0].length, len: g[0].length });
  }
  let out = "";
  let pos = 0;
  let i = 0;
  while (i < groups.length) {
    const first = groups[i] as { start: number };
    let best = -1;
    let count = 0;
    let digits = "";
    for (let j = i; j < groups.length; j++) {
      const g = groups[j] as { start: number; end: number; len: number };
      // Grouped PANs (4-4-4-4, 4-6-5, …) never have a short inner group: "100 200 300 …" is not a card.
      if (j > i && (groups[j - 1] as { len: number }).len < 4) break;
      count += g.len;
      if (count > 19) break;
      digits += match.slice(g.start, g.end);
      if (count >= 13 && isLikelyCardNumber(digits)) best = j;
    }
    if (best === -1) {
      i += 1;
      continue;
    }
    out += match.slice(pos, first.start) + placeholder;
    pos = (groups[best] as { end: number }).end;
    i = best + 1;
  }
  return pos === 0 ? match : out + match.slice(pos);
}

function uuidRanges(text: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  for (const m of text.matchAll(UUID_RE)) {
    ranges.push([m.index ?? 0, (m.index ?? 0) + m[0].length]);
  }
  return ranges;
}

/** Next "http://" or "https://" at or after `from`: [start, schemeLength], or undefined. */
function nextUrl(lower: string, from: number): [number, number] | undefined {
  const http = lower.indexOf("http://", from);
  const https = lower.indexOf("https://", from);
  if (http !== -1 && (https === -1 || http < https)) return [http, 7];
  if (https !== -1) return [https, 8];
  return undefined;
}

/**
 * Remove query strings from the http(s) URL(s) inside one whitespace-free token.
 * Every `?…` segment up to the next `#` is dropped (fragments are kept). If a secret parameter
 * appears after a `?`, everything from that `?` to the end of the token is dropped.
 * A trailing `?` (sentence punctuation) is kept. Linear time.
 */
function stripUrlQueryInToken(token: string, sensitiveQueryRe: RegExp): string {
  const url = nextUrl(token.toLowerCase(), 0);
  if (!url) return token;
  let out = "";
  let pos = 0;
  let from = url[0] + url[1];
  let sensitiveAt = -2; // -2: not searched yet, -1: none at or after the last search position
  for (;;) {
    const q = token.indexOf("?", from);
    if (q === -1 || q === token.length - 1) break;
    if (token[q + 1] === "#") {
      from = q + 1;
      continue;
    }
    if (sensitiveAt === -2 || (sensitiveAt !== -1 && sensitiveAt < q)) {
      sensitiveQueryRe.lastIndex = q;
      const m = sensitiveQueryRe.exec(token);
      sensitiveAt = m ? m.index : -1;
    }
    if (sensitiveAt !== -1) return out + token.slice(pos, q);
    const hash = token.indexOf("#", q);
    out += token.slice(pos, q);
    if (hash === -1) return out;
    pos = hash;
    from = hash;
  }
  return out + token.slice(pos);
}

export function compileBuiltIn(name: BuiltInDetectorName, cfg: DetectorConfig): CompiledDetector {
  const p = cfg.placeholders;
  switch (name) {
    case "email":
      return { name, apply: (t) => (t.includes("@") ? t.replace(EMAIL_RE, p.email) : t) };
    case "jwt":
      return { name, apply: (t) => (t.includes("eyJ") ? t.replace(JWT_RE, p.token) : t) };
    case "bearer":
      return { name, apply: (t) => t.replace(BEARER_RE, p.bearer) };
    case "apiKey":
      return { name, apply: (t) => t.replace(API_KEY_RE, p.apiKey) };
    case "iban":
      return {
        name,
        apply: (t) =>
          t.replace(IBAN_RE, (m) => {
            const expected = ibanLength(m.slice(0, 2));
            if (expected === undefined) return m;
            // The greedy match may include a trailing word (e.g. " EUR"): cut at the expected length.
            let seen = 0;
            let cut = 0;
            while (cut < m.length && seen < expected) {
              if (m[cut] !== " ") seen += 1;
              cut += 1;
            }
            if (seen < expected) return m;
            if (cut < m.length && m[cut] !== " ") return m;
            const candidate = m.slice(0, cut).replace(/ /g, "");
            return isValidIban(candidate) ? p.iban + m.slice(cut) : m;
          }),
      };
    case "card":
      return {
        name,
        apply: (t) => {
          if (!/\d{4}/.test(t) && !/\d[ -]\d/.test(t)) return t;
          return t.replace(CARD_RE, (m, offset: number) => {
            if (m.length < 13) return m; // fewer than 13 characters cannot hold 13 digits
            const end = offset + m.length;
            // Only UUIDs overlapping this run matter, and they lie within 36 chars of it: one local
            // scan per candidate run keeps the detector linear and skips the UUID scan for most text.
            const from = Math.max(0, offset - 36);
            const uuids = uuidRanges(t.slice(from, end + 36)).map(([s, e]): [number, number] => [
              s + from,
              e + from,
            ]);
            // Scrub only the parts of the run outside UUIDs, so a card next to a UUID is still found.
            let out = "";
            let pos = offset;
            for (const [s, e] of uuids) {
              if (e <= pos) continue;
              if (s >= end) break;
              if (s > pos) out += replaceCardSpans(t.slice(pos, s), p.card);
              out += t.slice(Math.max(s, pos), Math.min(e, end));
              pos = Math.min(e, end);
            }
            return pos === offset
              ? replaceCardSpans(m, p.card)
              : out + replaceCardSpans(t.slice(pos, end), p.card);
          });
        },
      };
    case "phone":
      return {
        name,
        apply: (t) => t.replace(PHONE_E164_RE, p.phone).replace(PHONE_NANP_RE, p.phone),
      };
    case "ipv4":
      return {
        name,
        apply: (t) => t.replace(IPV4_RE, (m) => (isValidIpv4(m) ? p.ip : m)),
      };
    case "ipv6":
      return {
        name,
        apply: (t) =>
          t.includes(":") ? t.replace(IPV6_RE, (m) => (m.includes(":") && isValidIpv6(m) ? p.ip : m)) : t,
      };
    case "queryParam": {
      const re = new RegExp(`([?&](?:${namesAlternation(cfg.secretNames)})=)[^&\\s]+`, "gi");
      return { name, apply: (t) => t.replace(re, (_m, prefix: string) => prefix + p.redacted) };
    }
    case "keyValue": {
      const re = new RegExp(`\\b(${namesAlternation(cfg.secretNames)})\\s*=\\s*[^\\s&]+`, "gi");
      return { name, apply: (t) => t.replace(re, (_m, key: string) => `${key}=${p.redacted}`) };
    }
    case "jsonSecret": {
      const re = new RegExp(
        `("(?:${namesAlternation(cfg.secretNames)})"\\s*:\\s*)"(?:[^"\\\\\\n]|\\\\.)*"`,
        "gi",
      );
      return {
        name,
        apply: (t) =>
          t.includes('"') ? t.replace(re, (_m, prefix: string) => `${prefix}"${p.redacted}"`) : t,
      };
    }
    case "cookieHeader":
      return {
        name,
        apply: (t) => t.replace(COOKIE_HEADER_RE, (_m, header: string) => `${header}: ${p.cookie}`),
      };
    case "authorizationHeader":
      return {
        name,
        apply: (t) => t.replace(AUTHORIZATION_HEADER_RE, (_m, header: string) => `${header}: ${p.bearer}`),
      };
    case "secretHeader":
      return {
        name,
        apply: (t) =>
          /x-/i.test(t)
            ? t.replace(
                SECRET_HEADER_RE,
                (_m, header: string) => `${header}: ${/key$/i.test(header) ? p.apiKey : p.token}`,
              )
            : t,
      };
    case "urlCredentials":
      return {
        name,
        apply: (t) => (t.includes("://") ? t.replace(URL_CREDENTIALS_RE, () => `://${p.redacted}@`) : t),
      };
    case "urlQuery": {
      const sensitiveQueryRe = new RegExp(`[?&](?:${namesAlternation([...cfg.secretNames, "key"])})=`, "i");
      return {
        name,
        apply: (t) => {
          // Visit only the whitespace-free tokens that contain a URL. Linear: each char is seen O(1) times.
          let out = "";
          let pos = 0;
          URL_START_RE.lastIndex = 0;
          for (let m = URL_START_RE.exec(t); m; m = URL_START_RE.exec(t)) {
            let start = m.index;
            while (start > pos && !/\s/.test(t[start - 1] as string)) start -= 1;
            SPACE_RE.lastIndex = m.index;
            const end = SPACE_RE.exec(t)?.index ?? t.length;
            out += t.slice(pos, start) + stripUrlQueryInToken(t.slice(start, end), sensitiveQueryRe);
            pos = end;
            URL_START_RE.lastIndex = end;
          }
          return pos === 0 ? t : out + t.slice(pos);
        },
      };
    }
    case "contextId": {
      const re = new RegExp(
        `\\b(${namesAlternation(cfg.contextIdNames)})(\\s*[=:]\\s*)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b`,
        "gi",
      );
      return {
        name,
        apply: (t, ctx) =>
          t.replace(re, (_m, key: string, sep: string, uuid: string) => {
            const norm = uuid.toLowerCase();
            let id = ctx.ids.get(norm);
            if (id === undefined) {
              id = p.id.replace("{n}", String(ctx.ids.size + 1));
              ctx.ids.set(norm, id);
            }
            return `${key}${sep}${id}`;
          }),
      };
    }
  }
}

export function compileCustom(d: CustomDetector, p: Placeholders): CompiledDetector {
  if (!d || typeof d.name !== "string" || !(d.pattern instanceof RegExp)) {
    throw new TypeError("pii-scrub: a custom detector needs a string `name` and a RegExp `pattern`");
  }
  const flags = d.pattern.flags.includes("g") ? d.pattern.flags : `${d.pattern.flags}g`;
  const re = new RegExp(d.pattern.source, flags);
  const replacement = d.replacement ?? p.redacted;
  const replace = typeof replacement === "function" ? replacement : () => replacement;
  const validate = d.validate;
  return {
    name: d.name,
    apply: (t) =>
      t.replace(re, (m: string) => {
        if (m === "") return m;
        if (validate && !validate(m)) return m;
        return replace(m);
      }),
  };
}
