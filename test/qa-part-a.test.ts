import { describe, expect, it } from "vitest";
import { createScrubber, scrub, scrubText } from "../src/index.js";

describe("secret headers, AWS secret, URL credentials", () => {
  it("redacts X-Api-Key and X-*-Token header values", () => {
    expect(scrubText("curl -H 'X-Api-Key: 9f8e7d6c5b4a39281706f5e4d3c2b1a0'")).toBe(
      "curl -H 'X-Api-Key: [api-key]'",
    );
    expect(scrubText("x-auth-token: abc.def-123")).toBe("x-auth-token: [token]");
    expect(scrubText("X-Shopify-Access-Token:shpat_123")).toBe("X-Shopify-Access-Token: [token]");
    expect(scrubText("X-Token: abc123")).toBe("X-Token: [token]");
  });
  it("keeps unrelated X- headers", () => {
    expect(scrubText("X-Request-Id: 42")).toBe("X-Request-Id: 42");
    expect(scrubText("X-Token-Count: 5")).toBe("X-Token-Count: 5");
  });
  it("redacts aws_secret_access_key=", () => {
    expect(scrubText("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")).toBe(
      "aws_secret_access_key=[redacted]",
    );
  });
  it("redacts user:pass@ in URLs and keeps the host", () => {
    expect(scrubText("https://user:hunter2pass@db.example.com/x")).toBe(
      "https://[redacted]@db.example.com/x",
    );
    expect(scrubText("postgres://app:s3cr3t@10.0.0.1:5432/db")).toBe(
      "postgres://[redacted]@10.0.0.1:5432/db",
    );
    expect(scrubText("see https://example.com/a:b@c")).toBe("see https://example.com/a:b@c");
    expect(scrubText("mailto jane@example.com")).toBe("mailto [email]");
  });
});

describe("card false positives on short groups", () => {
  it("keeps short space-separated groups", () => {
    expect(scrubText("counts 100 200 300 400 500 600 700")).toBe("counts 100 200 300 400 500 600 700");
  });
  it("still finds grouped and contiguous cards", () => {
    expect(scrubText("order 12345 4111 1111 1111 1111")).toBe("order 12345 [card]");
    expect(scrubText("qty 2 4242 4242 4242 4242 exp 12/29")).toBe("qty 2 [card] exp 12/29");
    expect(scrubText("amex 3782 822463 10005")).toBe("amex [card]");
    expect(scrubText("9 4111 1111 1111 1111 7")).toBe("9 [card] 7");
  });
  it("skips digit runs inside UUIDs with many UUIDs and runs", () => {
    const uuid = "a0000000-0000-4000-8000-000000000001";
    const line = `${uuid} 4111111111111111 ${uuid} 1730284800000\n`;
    expect(scrubText(line.repeat(3))).toBe(`${uuid} [card] ${uuid} 1730284800000\n`.repeat(3));
  });
});

describe("soft traversal limits (onLimit: 'scrub')", () => {
  const soft = (o: Record<string, unknown>) => createScrubber({ onLimit: "scrub", ...o });
  it("default stays backward compatible", () => {
    expect(createScrubber({ maxDepth: 1 }).value({ a: { b: { c: "x" } } })).toEqual({
      a: { b: "[truncated]" },
    });
  });
  it("scrubs past maxDepth", () => {
    const out = soft({ maxDepth: 2 }).value({ a: { b: { c: { d: { token: "t", email: "x@y.io" } } } } });
    expect(out).toEqual({ a: { b: { c: { d: { token: "[token]", email: "[email]" } } } } });
  });
  it("scrubs past maxNodes", () => {
    const items = Array.from({ length: 20 }, (_, i) => ({ id: i, payload: { email: `u${i}@x.io` } }));
    const out = soft({ maxNodes: 3 }).value({ items }) as { items: Array<{ payload: { email: string } }> };
    expect(out.items[19]?.payload.email).toBe("[email]");
  });
  it("truncates containers past the hard caps but never leaks strings", () => {
    const out = soft({ maxNodes: 1, hardMaxNodes: 2 }).value({ a: "x@y.io", b: { c: "x@y.io" } });
    expect(out).toEqual({ a: "[email]", b: "[truncated]" });
    let deep: unknown = "x@y.io";
    for (let i = 0; i < 300; i++) deep = { d: deep };
    expect(JSON.stringify(soft({}).value(deep))).not.toContain("x@y.io");
  });
  it("validates onLimit", () => {
    expect(() => createScrubber({ onLimit: "nope" as "scrub" })).toThrow(TypeError);
  });
  it("circular input does not throw", () => {
    const o: Record<string, unknown> = { email: "a@b.io" };
    o.self = o;
    expect(() => scrub(o)).not.toThrow();
  });
});

describe("performance and ReDoS (QA perf.mjs inputs)", () => {
  const N = 64 * 1024;
  const time = (s: string) => {
    let best = Number.POSITIVE_INFINITY;
    for (let i = 0; i < 3; i++) {
      const t = performance.now();
      scrubText(s);
      best = Math.min(best, performance.now() - t);
    }
    return best;
  };
  const limit = Number(process.env.REDOS_64K_LIMIT_MS ?? 50);
  const adv: Record<string, string> = {
    "1 ": "1 ".repeat(N / 2),
    "1-": "1-".repeat(N / 2),
    "1×": "1".repeat(N),
    "a.@": `${"a.".repeat(N / 2)}@`,
    "@a.": "@a.".repeat(Math.floor(N / 3)),
    "1.": "1.".repeat(N / 2),
    "eyJaaaaaaaa.": "eyJaaaaaaaa.".repeat(Math.floor(N / 12)),
    "https://a?": "https://a?".repeat(Math.floor(N / 10)),
    "DE89 ": "DE89 ".repeat(Math.floor(N / 5)),
    "x-a-": "x-a-".repeat(N / 4),
    "http://a:": "http://a:".repeat(Math.floor(N / 9)),
  };
  for (const [name, s] of Object.entries(adv)) {
    it(`64 KB '${name}' < ${limit} ms`, () => {
      expect(time(s)).toBeLessThan(limit);
    });
  }
  it("card detector is linear with many UUIDs (1 MB)", () => {
    const line = "a0000000-0000-4000-8000-000000000001 4111 1111 1111 1111 order 12345\n";
    const s = line.repeat(Math.ceil(1e6 / line.length));
    expect(time(s)).toBeLessThan(Number(process.env.LINEAR_1MB_LIMIT_MS ?? 400));
  });
});
