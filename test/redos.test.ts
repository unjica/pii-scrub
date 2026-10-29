import { describe, expect, it } from "vitest";
import { type BuiltInDetectorName, createScrubber } from "../src/index.js";

/**
 * ReDoS guard: adversarial inputs (~100 KB) for every detector must finish quickly.
 * A catastrophic (exponential or quadratic) regex would take seconds to minutes on these sizes.
 * The bound is generous for slow CI machines; typical timings are a few milliseconds.
 */
const SIZE = 100_000;
const LIMIT_MS = Number(process.env.REDOS_LIMIT_MS ?? 1500);
const fill = (unit: string, prefix = "", suffix = ""): string =>
  prefix + unit.repeat(Math.ceil((SIZE - prefix.length - suffix.length) / unit.length)) + suffix;

const ADVERSARIAL: Record<BuiltInDetectorName, string[]> = {
  email: [
    fill("a"),
    `${fill("a.")}@`,
    fill("a@"),
    fill("a.", "a@"),
    fill("-", "a@"),
    fill("a.a@b.", "", "c"),
    fill("@a."),
  ],
  jwt: [fill("eyJ"), fill("a", "eyJ", ".a"), fill("eyJaaaaaaaaa."), fill("a.", "eyJaaaaaaaaa.")],
  bearer: [fill("Bearer "), fill(" ", "Bearer"), fill("=", "Bearer "), fill("Bearer a")],
  apiKey: [fill("sk-"), fill("a", "sk-", "!"), fill("a", "ghp_"), fill("a", "sk_live_", "_"), fill("AKIA")],
  iban: [fill("DE89 "), fill(" A", "DE89"), fill("A"), fill("DE89")],
  card: [fill("1 "), fill("1-"), fill(" ", "1", "1"), fill("4111"), fill("1 -"), fill("1   ")],
  phone: [fill("+1 "), fill(" -", "+1"), fill("(555) "), fill("1", "+1"), fill("555-")],
  ipv6: [fill(":"), fill("a:"), fill("f"), fill("1:"), fill("::1."), fill("a", "", ":")],
  ipv4: [fill("1."), fill("1.1.1.1."), fill("255.")],
  queryParam: [fill("?token="), fill("&password=a")],
  keyValue: [fill("token "), fill(" ", "token"), fill("=", "password=")],
  jsonSecret: [fill('"password":"'), fill("\\", '"password":"'), fill(" ", '"token"'), fill('"token":')],
  cookieHeader: [fill("cookie:"), fill(" ", "cookie"), fill("set-cookie ")],
  authorizationHeader: [fill("authorization "), fill(" ", "authorization")],
  urlQuery: [
    fill("http://"),
    fill("https://a?"),
    fill("a", "http://"),
    fill("?a#", "http://x"),
    fill("?token=", "http://x"),
  ],
  contextId: [fill("user_id="), fill(" ", "user_id"), fill("a0000000-", "user_id=")],
};

describe("ReDoS resistance", () => {
  const all = createScrubber({ detectors: { ipv4: true, ipv6: true } });
  for (const [name, inputs] of Object.entries(ADVERSARIAL)) {
    it(`${name}: ${inputs.length} adversarial inputs of ~${SIZE / 1000} KB each finish under ${LIMIT_MS} ms`, () => {
      for (const input of inputs) {
        const start = performance.now();
        all.text(input);
        const elapsed = performance.now() - start;
        expect(
          elapsed,
          `${name} took ${elapsed.toFixed(1)} ms on ${JSON.stringify(input.slice(0, 30))}…`,
        ).toBeLessThan(LIMIT_MS);
      }
    });
  }

  it("a large mixed payload is scrubbed in roughly linear time", () => {
    const line =
      "user bob@example.com paid with 4111 1111 1111 1111 token=abc https://x.io/a?b=1 +386 40 123 456\n";
    const small = line.repeat(500);
    const big = line.repeat(5000);
    const t0 = performance.now();
    all.text(small);
    const t1 = performance.now();
    all.text(big);
    const t2 = performance.now();
    expect(t2 - t1).toBeLessThan(LIMIT_MS);
    // 10x input should not cost more than ~40x time (quadratic would be ~100x).
    expect((t2 - t1) / Math.max(t1 - t0, 1)).toBeLessThan(40);
  });

  it("a huge object graph is bounded by maxNodes", () => {
    const wide = { items: Array.from({ length: 200_000 }, (_, i) => ({ i, note: "x@y.io" })) };
    const start = performance.now();
    const out = all.value(wide) as { items: unknown[] };
    expect(performance.now() - start).toBeLessThan(LIMIT_MS);
    expect(out.items).toHaveLength(200_000);
    expect(out.items[199_999]).toBe("[truncated]");
  });
});
