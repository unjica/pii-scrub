/** Names of the built-in free-text detectors, in the order they run. */
export type BuiltInDetectorName =
  | "urlCredentials"
  | "email"
  | "jwt"
  | "bearer"
  | "apiKey"
  | "iban"
  | "card"
  | "phone"
  | "ipv6"
  | "ipv4"
  | "queryParam"
  | "keyValue"
  | "jsonSecret"
  | "cookieHeader"
  | "authorizationHeader"
  | "secretHeader"
  | "urlQuery"
  | "contextId";

/** Placeholder kinds. Each built-in replacement uses one of these. */
export interface Placeholders {
  email: string;
  token: string;
  bearer: string;
  apiKey: string;
  card: string;
  phone: string;
  iban: string;
  ip: string;
  ssn: string;
  password: string;
  secret: string;
  cookie: string;
  redacted: string;
  /** Correlation id for UUIDs in a user/session/account context. `{n}` is replaced by a counter. */
  id: string;
  truncated: string;
  circular: string;
}

/** A user-supplied free-text detector. */
export interface CustomDetector {
  /** Identifier used in error messages and documentation. */
  name: string;
  /**
   * Pattern to search for. The global flag is added automatically.
   * Keep it linear: avoid nested quantifiers such as `(a+)+` and prefer bounded repeats.
   */
  pattern: RegExp;
  /**
   * Replacement for each match: a literal string (no `$1` expansion) or a function.
   * Defaults to the `redacted` placeholder.
   */
  replacement?: string | ((match: string) => string);
  /** Optional extra check; return false to keep the match unchanged. */
  validate?: (match: string) => boolean;
}

export interface ScrubOptions {
  /** Enable or disable built-in detectors. `ipv4` and `ipv6` are off by default; all others are on. */
  detectors?: Partial<Record<BuiltInDetectorName, boolean>>;
  /** Extra detectors. They run before the built-in detectors, in array order. */
  customDetectors?: readonly CustomDetector[];
  /** Override placeholder strings. */
  placeholders?: Partial<Placeholders>;
  /**
   * Extra sensitive object keys (matched case-insensitively, ignoring non-alphanumerics,
   * so `api_key`, `apiKey` and `API-KEY` are equal).
   * - array: values become the `redacted` placeholder (built-in keys keep their typed placeholder)
   * - record: key → literal placeholder (overrides built-in keys)
   */
  sensitiveKeys?: readonly string[] | Readonly<Record<string, string>>;
  /** Use the built-in sensitive key list (email, password, token, cardNumber, …). Default true. */
  defaultSensitiveKeys?: boolean;
  /**
   * Names treated as secrets by the `queryParam`, `keyValue` and `jsonSecret` detectors
   * (`?token=…`, `password=…`, `"secret": "…"`). Replaces the default list.
   * `_` and `-` in a name also match the other separator or no separator.
   */
  secretNames?: readonly string[];
  /** Key names whose UUID value becomes a correlation id (`user_id=[id:1]`). Replaces the default list. */
  contextIdNames?: readonly string[];
  /**
   * What happens past `maxDepth`/`maxNodes`:
   * - `"truncate"` (default): containers past the limit become the `truncated` placeholder
   * - `"scrub"`: the limits are soft; traversal continues and still scrubs strings and sensitive
   *   keys, up to the hard caps `hardMaxDepth`/`hardMaxNodes`, after which containers are truncated
   */
  onLimit?: "truncate" | "scrub";
  /** Hard node cap for `onLimit: "scrub"`. Default 10 000 (or `maxNodes` if larger). */
  hardMaxNodes?: number;
  /** Hard depth cap for `onLimit: "scrub"`. Default 128 (or `maxDepth` if larger). */
  hardMaxDepth?: number;
  /** Maximum nesting depth for objects/arrays/errors. Deeper containers become the `truncated` placeholder. Default 32. */
  maxDepth?: number;
  /**
   * Maximum number of nodes visited per call. After the limit, strings are still scrubbed
   * but containers become the `truncated` placeholder. Default 10 000.
   */
  maxNodes?: number;
}

export interface Scrubber {
  /** Scrub free-form text. */
  text(input: string): string;
  /** Deep-scrub any value (strings, arrays, plain objects, Errors, Maps, Sets). Never mutates the input. */
  value<T>(input: T): T;
  /** Scrub an Error (message, stack, cause, own properties) into a new Error with the same prototype. */
  error<T>(input: T): T;
}
