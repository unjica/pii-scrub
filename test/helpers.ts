import { passesLuhn } from "../src/index.js";

/** Small deterministic PRNG (mulberry32) so fuzz failures are reproducible from the seed. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const pick = <T>(r: () => number, items: readonly T[]): T =>
  items[Math.floor(r() * items.length)] as T;
export const int = (r: () => number, min: number, max: number): number =>
  min + Math.floor(r() * (max - min + 1));

export function randomDigits(r: () => number, n: number): string {
  let s = "";
  for (let i = 0; i < n; i++) s += String(int(r, 0, 9));
  return s;
}

/** A Luhn-valid 16-digit number starting with the given prefix. */
export function luhnNumber(r: () => number, prefix = "4", length = 16): string {
  for (;;) {
    const body = prefix + randomDigits(r, length - prefix.length - 1);
    for (let d = 0; d <= 9; d++) if (passesLuhn(body + d)) return body + d;
  }
}

const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
export function alnum(r: () => number, n: number): string {
  let s = "";
  for (let i = 0; i < n; i++) s += ALNUM[int(r, 0, ALNUM.length - 1)];
  return s;
}

/** Secrets that must never survive scrubbing, paired with a generator. */
export const SECRET_GENERATORS: ReadonlyArray<[string, (r: () => number) => string]> = [
  ["email", (r) => `${alnum(r, int(r, 1, 12))}.${alnum(r, 3)}@${alnum(r, int(r, 2, 10))}.example.com`],
  ["jwt", (r) => `eyJ${alnum(r, 20)}.eyJ${alnum(r, 30)}.${alnum(r, 43)}`],
  ["bearer", (r) => `Bearer ${alnum(r, 32)}`],
  ["openai", (r) => `sk-proj-${alnum(r, 40)}`],
  ["github", (r) => `ghp_${alnum(r, 36)}`],
  ["aws", (r) => `AKIA${alnum(r, 16).toUpperCase()}`],
  ["card-visa", (r) => luhnNumber(r, "4")],
  ["card-mc-spaced", (r) => luhnNumber(r, "5").match(/.{4}/g)?.join(" ") ?? ""],
  ["phone-e164", (r) => `+386${randomDigits(r, 8)}`],
  ["phone-nanp", (r) => `(${int(r, 200, 999)}) ${int(r, 200, 999)}-${randomDigits(r, 4)}`],
  ["iban", () => "SI56 2633 0001 2039 086"],
  ["password-kv", (r) => `password=${alnum(r, 14)}`],
  ["token-query", (r) => `https://api.example.com/cb?access_token=${alnum(r, 24)}`],
  ["json-secret", (r) => `{"client_secret":"${alnum(r, 24)}"}`],
];

/** The part of a seeded secret that must not appear in the output. */
export function sensitivePart(kind: string, secret: string): string {
  switch (kind) {
    case "bearer":
      return secret.slice("Bearer ".length);
    case "password-kv":
      return secret.slice("password=".length);
    case "token-query":
      return secret.slice(secret.indexOf("=") + 1);
    case "json-secret":
      return secret.slice('{"client_secret":"'.length, -2);
    default:
      return secret;
  }
}
