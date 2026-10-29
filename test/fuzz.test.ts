import { describe, expect, it } from "vitest";
import { createScrubber } from "../src/index.js";
import { alnum, int, pick, rng, SECRET_GENERATORS, sensitivePart } from "./helpers.js";

const ITERATIONS = Number(process.env.FUZZ_ITERATIONS ?? 1500);
const defaults = createScrubber();
const allOn = createScrubber({ detectors: { ipv4: true, ipv6: true } });

const ATOMS = [
  " ",
  "\n",
  "\t",
  "@",
  ".",
  "-",
  "_",
  ":",
  "=",
  "&",
  "?",
  "#",
  "/",
  "+",
  "(",
  ")",
  '"',
  "\\",
  "[",
  "]",
  "eyJ",
  "Bearer ",
  "sk-",
  "ghp_",
  "http://",
  "https://",
  "token",
  "password",
  "cookie:",
  "authorization:",
  "user_id=",
  "DE89",
  "4111",
  "+1",
  "::",
  "0",
  "1",
  "9",
  "a",
  "Z",
  "ž",
  "🙂",
  "\u0000",
  "\u2028",
];

function randomText(r: () => number, maxLen: number): string {
  let s = "";
  const len = int(r, 0, maxLen);
  while (s.length < len) s += r() < 0.6 ? pick(r, ATOMS) : alnum(r, int(r, 1, 8));
  return s;
}

const SEPARATORS = [" ", "\n", "\t", ", ", "; ", " (", ") ", ' "', '" ', ": "];

function randomValue(r: () => number, depth: number): unknown {
  const roll = r();
  if (depth > 4 || roll < 0.35)
    return pick(r, [randomText(r, 60), int(r, -1e6, 1e6), r() < 0.5, null, undefined]);
  if (roll < 0.55) return Array.from({ length: int(r, 0, 5) }, () => randomValue(r, depth + 1));
  if (roll < 0.6) return new Error(randomText(r, 40));
  const obj: Record<string, unknown> = {};
  for (let i = int(r, 0, 6); i > 0; i--) {
    const key =
      r() < 0.3 ? pick(r, ["email", "Password", "api_key", "note", "msg", "token", "data"]) : alnum(r, 5);
    obj[key] = randomValue(r, depth + 1);
  }
  return obj;
}

describe("fuzz", () => {
  it(`random text never throws and scrubbing is idempotent (${ITERATIONS} cases × 2 configs)`, () => {
    const r = rng(0xc0ffee);
    for (let i = 0; i < ITERATIONS; i++) {
      const input = randomText(r, 400);
      for (const s of [defaults, allOn]) {
        const once = s.text(input);
        expect(typeof once).toBe("string");
        expect(s.text(once), `seed case ${i}: ${JSON.stringify(input)}`).toBe(once);
      }
    }
  });

  it(`random nested values never throw, are idempotent and do not mutate input (${ITERATIONS} cases)`, () => {
    const r = rng(0xbeef);
    for (let i = 0; i < ITERATIONS; i++) {
      const input = randomValue(r, 0);
      const before = JSON.stringify(input);
      const once = allOn.value(input);
      expect(JSON.stringify(input)).toBe(before);
      expect(JSON.stringify(allOn.value(once))).toBe(JSON.stringify(once));
    }
  });

  it(`seeded secrets never leak from text (${ITERATIONS} documents)`, () => {
    const r = rng(42);
    for (let i = 0; i < ITERATIONS; i++) {
      const planted: Array<[string, string]> = [];
      let doc = randomText(r, 80).replace(/[\w@.+-]+$/, "");
      for (let j = int(r, 1, 4); j > 0; j--) {
        const [kind, gen] = pick(r, SECRET_GENERATORS);
        const secret = gen(r);
        planted.push([kind, secret]);
        doc += pick(r, SEPARATORS) + secret + pick(r, SEPARATORS) + alnum(r, int(r, 0, 6));
      }
      const out = defaults.text(doc);
      for (const [kind, secret] of planted) {
        expect(out, `${kind} leaked in case ${i}: ${JSON.stringify(doc)}`).not.toContain(
          sensitivePart(kind, secret),
        );
      }
    }
  });

  it(`seeded secrets never leak from nested objects or Errors (${ITERATIONS} payloads)`, () => {
    const r = rng(7);
    for (let i = 0; i < ITERATIONS; i++) {
      const [kind, gen] = pick(r, SECRET_GENERATORS);
      const secret = gen(r);
      const leaf = r() < 0.5 ? `note ${secret} end` : new Error(`failed ${secret}`);
      let node: unknown = leaf;
      for (let d = int(r, 0, 8); d > 0; d--)
        node = r() < 0.5 ? [node, randomValue(r, 3)] : { [alnum(r, 4)]: node };
      const out = defaults.value(node);
      const serialized = JSON.stringify(out, (_k, v) =>
        v instanceof Error ? { m: v.message, s: v.stack } : v,
      );
      expect(serialized, `${kind} leaked in case ${i}`).not.toContain(sensitivePart(kind, secret));
    }
  });
});
