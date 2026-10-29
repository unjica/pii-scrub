import {
  BUILT_IN_DETECTORS,
  type CompiledDetector,
  compileBuiltIn,
  compileCustom,
  DEFAULT_CONTEXT_ID_NAMES,
  DEFAULT_DISABLED,
  DEFAULT_SECRET_NAMES,
  type ScrubContext,
} from "./detectors.js";
import type { Placeholders, Scrubber, ScrubOptions } from "./types.js";

export const DEFAULT_PLACEHOLDERS: Readonly<Placeholders> = Object.freeze({
  email: "[email]",
  token: "[token]",
  bearer: "[bearer-token]",
  apiKey: "[api-key]",
  card: "[card]",
  phone: "[phone]",
  iban: "[iban]",
  ip: "[ip]",
  ssn: "[ssn]",
  password: "[password]",
  secret: "[secret]",
  cookie: "[cookie]",
  redacted: "[redacted]",
  id: "[id:{n}]",
  truncated: "[truncated]",
  circular: "[circular]",
});

/** Built-in sensitive keys (normalized: lower-case, alphanumerics only) → placeholder kind. */
export const DEFAULT_SENSITIVE_KEYS: Readonly<Record<string, keyof Placeholders>> = Object.freeze({
  email: "email",
  emailaddress: "email",
  useremail: "email",
  mail: "email",
  phone: "phone",
  phonenumber: "phone",
  mobile: "phone",
  cellphone: "phone",
  ssn: "ssn",
  password: "password",
  passwd: "password",
  secret: "secret",
  clientsecret: "secret",
  privatekey: "secret",
  token: "token",
  accesstoken: "token",
  refreshtoken: "token",
  idtoken: "token",
  apikey: "apiKey",
  apisecret: "apiKey",
  authorization: "bearer",
  auth: "token",
  cookie: "cookie",
  setcookie: "cookie",
  creditcard: "card",
  cardnumber: "card",
  cvv: "card",
  cvc: "card",
  iban: "iban",
});

const DEFAULT_MAX_DEPTH = 32;
const DEFAULT_MAX_NODES = 10_000;

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function isErrorLike(value: object): value is Error {
  return value instanceof Error || Object.prototype.toString.call(value) === "[object Error]";
}

function isBinary(value: object): boolean {
  return ArrayBuffer.isView(value) || value instanceof ArrayBuffer;
}

function defineValue(target: object, key: PropertyKey, value: unknown, enumerable = true): void {
  // defineProperty avoids triggering `__proto__` setters on keys that came from untrusted JSON.
  Object.defineProperty(target, key, { value, enumerable, writable: true, configurable: true });
}

function positiveInt(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || Number.isNaN(value) || value < 0) {
    throw new RangeError(`pii-scrub: ${name} must be a non-negative number`);
  }
  return value;
}

/** Create a reusable scrubber. Compiling options once is cheaper than passing them on every call. */
export function createScrubber(options: ScrubOptions = {}): Scrubber {
  const placeholders: Placeholders = { ...DEFAULT_PLACEHOLDERS, ...options.placeholders };
  const maxDepth = positiveInt(options.maxDepth, DEFAULT_MAX_DEPTH, "maxDepth");
  const maxNodes = positiveInt(options.maxNodes, DEFAULT_MAX_NODES, "maxNodes");
  const cfg = {
    placeholders,
    secretNames: options.secretNames ?? DEFAULT_SECRET_NAMES,
    contextIdNames: options.contextIdNames ?? DEFAULT_CONTEXT_ID_NAMES,
  };

  const toggles = options.detectors ?? {};
  for (const key of Object.keys(toggles)) {
    if (!(BUILT_IN_DETECTORS as readonly string[]).includes(key)) {
      throw new TypeError(`pii-scrub: unknown detector "${key}"`);
    }
  }
  const pipeline: CompiledDetector[] = [];
  for (const custom of options.customDetectors ?? []) pipeline.push(compileCustom(custom, placeholders));
  for (const name of BUILT_IN_DETECTORS) {
    const enabled = toggles[name] ?? !DEFAULT_DISABLED.has(name);
    if (enabled) pipeline.push(compileBuiltIn(name, cfg));
  }

  // Key → placeholder. Explicit record entries override built-ins; array entries do not.
  const keyMap = new Map<string, string>();
  if (options.defaultSensitiveKeys !== false) {
    for (const [k, kind] of Object.entries(DEFAULT_SENSITIVE_KEYS)) keyMap.set(k, placeholders[kind]);
  }
  const extra = options.sensitiveKeys;
  if (Array.isArray(extra)) {
    for (const k of extra) {
      const n = normalizeKey(String(k));
      if (n && !keyMap.has(n)) keyMap.set(n, placeholders.redacted);
    }
  } else if (extra) {
    for (const [k, placeholder] of Object.entries(extra as Record<string, string>)) {
      const n = normalizeKey(k);
      if (n) keyMap.set(n, String(placeholder));
    }
  }

  function placeholderForKey(key: string): string | undefined {
    return keyMap.size === 0 ? undefined : keyMap.get(normalizeKey(key));
  }

  function scrubString(text: string, ctx: ScrubContext): string {
    let out = text;
    for (const d of pipeline) out = d.apply(out, ctx);
    return out;
  }

  function scrubDeep(input: unknown): unknown {
    const ctx: ScrubContext = { ids: new Map() };
    const done = new WeakMap<object, unknown>();
    const active = new WeakSet<object>();
    let nodes = 0;

    function keyed(key: string, child: unknown, depth: number): unknown {
      const placeholder = placeholderForKey(key);
      if (placeholder !== undefined && child !== null && child !== undefined) return placeholder;
      return walk(child, depth + 1);
    }

    function walk(node: unknown, depth: number): unknown {
      nodes += 1;
      if (typeof node === "string") return scrubString(node, ctx);
      if (node === null || typeof node !== "object") return node; // numbers, booleans, bigint, symbols, functions
      if (active.has(node)) return placeholders.circular;
      const cached = done.get(node);
      if (cached !== undefined) return cached;
      if (nodes > maxNodes || depth > maxDepth) return placeholders.truncated;
      if (isBinary(node)) return node;
      if (node instanceof Date) return new Date(node.getTime());
      if (node instanceof RegExp) return node;

      active.add(node);
      let out: unknown;
      try {
        if (Array.isArray(node)) {
          const arr: unknown[] = new Array(node.length);
          for (let i = 0; i < node.length; i++) {
            if (i in node) arr[i] = walk(node[i], depth + 1);
          }
          out = arr;
        } else if (isErrorLike(node)) {
          out = scrubErrorObject(node, depth);
        } else if (node instanceof Map) {
          const map = new Map<unknown, unknown>();
          for (const [k, v] of node) {
            map.set(k, typeof k === "string" ? keyed(k, v, depth) : walk(v, depth + 1));
          }
          out = map;
        } else if (node instanceof Set) {
          const set = new Set<unknown>();
          for (const v of node) set.add(walk(v, depth + 1));
          out = set;
        } else {
          const obj: Record<string, unknown> = {};
          for (const key of Object.keys(node)) {
            let child: unknown;
            try {
              child = (node as Record<string, unknown>)[key];
            } catch {
              child = placeholders.redacted; // throwing getter: never let it break logging
            }
            defineValue(obj, key, keyed(key, child, depth));
          }
          out = obj;
        }
      } finally {
        active.delete(node);
      }
      done.set(node, out);
      return out;
    }

    function scrubErrorObject(err: Error, depth: number): Error {
      const out = Object.create(Object.getPrototypeOf(err)) as Error;
      const keys = new Set<string>(Object.getOwnPropertyNames(err));
      // `stack` may be an accessor on the prototype or the instance depending on the engine.
      keys.add("message");
      keys.add("stack");
      for (const key of keys) {
        const desc = Object.getOwnPropertyDescriptor(err, key);
        let value: unknown;
        try {
          value = (err as unknown as Record<string, unknown>)[key];
        } catch {
          continue;
        }
        if (value === undefined && !desc) continue;
        const enumerable = desc ? Boolean(desc.enumerable) : false;
        const placeholder = key === "message" || key === "stack" ? undefined : placeholderForKey(key);
        const scrubbed =
          placeholder !== undefined && value !== null && value !== undefined
            ? placeholder
            : walk(value, depth + 1);
        defineValue(out, key, scrubbed, enumerable);
      }
      return out;
    }

    return walk(input, 0);
  }

  return {
    text(input: string): string {
      if (typeof input !== "string") return input;
      return scrubString(input, { ids: new Map() });
    },
    value<T>(input: T): T {
      return scrubDeep(input) as T;
    },
    error<T>(input: T): T {
      return scrubDeep(input) as T;
    },
  };
}
