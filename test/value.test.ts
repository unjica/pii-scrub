import { describe, expect, it } from "vitest";
import { createScrubber, scrub, scrubError } from "../src/index.js";

describe("deep value scrubbing", () => {
  it("replaces sensitive keys case-insensitively with typed placeholders", () => {
    expect(
      scrub({
        Email: "user@example.com",
        API_KEY: "sk-abcdefghijklmnopqrstuvwxyz",
        authorization: "Bearer abc",
        cookie: "sid=1",
        "card-number": 4111111111111111,
        nested: { phone: "+15551212", safe: "ok", password: { deep: true } },
      }),
    ).toEqual({
      Email: "[email]",
      API_KEY: "[api-key]",
      authorization: "[bearer-token]",
      cookie: "[cookie]",
      "card-number": "[card]",
      nested: { phone: "[phone]", safe: "ok", password: "[password]" },
    });
  });

  it("keeps null/undefined under sensitive keys", () => {
    expect(scrub({ email: null, token: undefined })).toEqual({ email: null, token: undefined });
  });

  it("leaves non-sensitive payloads equal", () => {
    const props = { path: "/checkout", status: 500, ok: true, flags: ["beta"], meta: { attempt: 2 } };
    expect(scrub(props)).toEqual(props);
  });

  it("scrubs strings under non-sensitive keys and inside arrays", () => {
    expect(scrub({ items: [{ email: "a@b.com" }, { msg: "hi user@x.io" }], n: 3 })).toEqual({
      items: [{ email: "[email]" }, { msg: "hi [email]" }],
      n: 3,
    });
    expect(scrub(["a@b.co", 1, null])).toEqual(["[email]", 1, null]);
    expect(scrub("x@y.io")).toBe("[email]");
  });

  it("never mutates input", () => {
    const input = { email: "a@b.co", list: ["x@y.io"], err: new Error("token=abc") };
    const snapshot = JSON.stringify(input);
    const out = scrub(input);
    expect(JSON.stringify(input)).toBe(snapshot);
    expect(input.err.message).toBe("token=abc");
    expect(out).not.toBe(input);
    expect(out.list).not.toBe(input.list);
  });

  it("protects against circular references and keeps shared references", () => {
    const shared = { note: "a@b.co" };
    const a: Record<string, unknown> = { shared, again: shared };
    a.self = a;
    const arr: unknown[] = [1];
    arr.push(arr);
    const out = scrub({ a, arr }) as { a: Record<string, unknown>; arr: unknown[] };
    expect(out.a.self).toBe("[circular]");
    expect(out.a.shared).toEqual({ note: "[email]" });
    expect(out.a.shared).toBe(out.a.again);
    expect(out.arr).toEqual([1, "[circular]"]);
    expect(() => JSON.stringify(out)).not.toThrow();
  });

  it("enforces maxDepth without leaking deeper strings", () => {
    const deep = { a: { b: { c: { d: "user@example.com" } } } };
    const out = createScrubber({ maxDepth: 2 }).value(deep);
    expect(out).toEqual({ a: { b: { c: "[truncated]" } } });
    expect(JSON.stringify(out)).not.toContain("@");
  });

  it("enforces maxNodes: strings still scrubbed, containers truncated", () => {
    const payload = { items: Array.from({ length: 20 }, (_, i) => ({ id: i, email: `u${i}@example.com` })) };
    const out = createScrubber({ maxNodes: 10 }).value(payload);
    const json = JSON.stringify(out);
    expect(json).toContain("[truncated]");
    expect(json).not.toMatch(/u\d+@example\.com/);
  });

  it("handles a very deep structure without stack overflow", () => {
    let node: Record<string, unknown> = { leaf: "x@y.io" };
    for (let i = 0; i < 50_000; i++) node = { next: node };
    expect(() => scrub(node)).not.toThrow();
  });

  it("handles Map, Set, Date, RegExp, binary and class instances", () => {
    class User {
      email = "a@b.co";
      name = "n";
    }
    const date = new Date(0);
    const bytes = new Uint8Array([1, 2]);
    const out = scrub({
      map: new Map<unknown, unknown>([
        ["password", "x"],
        ["note", "c@d.io"],
        [1, "e@f.io"],
      ]),
      set: new Set(["g@h.io"]),
      date,
      re: /x/,
      bytes,
      user: new User(),
    });
    expect(out.map).toEqual(
      new Map<unknown, unknown>([
        ["password", "[password]"],
        ["note", "[email]"],
        [1, "[email]"],
      ]),
    );
    expect(out.set).toEqual(new Set(["[email]"]));
    expect(out.date).toEqual(date);
    expect(out.date).not.toBe(date);
    expect(out.re).toBe(out.re);
    expect(out.bytes).toBe(bytes);
    expect(out.user).toEqual({ email: "[email]", name: "n" });
  });

  it("is safe against __proto__ keys from untrusted JSON", () => {
    const parsed = JSON.parse('{"__proto__": {"polluted": "a@b.co"}, "x": 1}');
    const out = scrub(parsed) as Record<string, unknown>;
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.getOwnPropertyDescriptor(out, "__proto__")?.value).toEqual({ polluted: "[email]" });
  });

  it("survives throwing getters", () => {
    const obj = {
      get boom(): string {
        throw new Error("nope");
      },
      ok: "x@y.io",
    };
    expect(scrub(obj)).toEqual({ boom: "[redacted]", ok: "[email]" });
  });

  it("sensitiveKeys: array uses [redacted], record sets placeholders, defaults can be disabled", () => {
    expect(
      scrub({ customerId: "c_1", Email: "a@b.co" }, { sensitiveKeys: ["customer_id", "email"] }),
    ).toEqual({
      customerId: "[redacted]",
      Email: "[email]",
    });
    expect(scrub({ email: "x", ssn: "1" }, { sensitiveKeys: { email: "<hidden>" } })).toEqual({
      email: "<hidden>",
      ssn: "[ssn]",
    });
    expect(scrub({ email: "plain", note: "a@b.co" }, { defaultSensitiveKeys: false })).toEqual({
      email: "plain",
      note: "[email]",
    });
  });

  it("correlation ids are stable across one value() call", () => {
    const id = "a0000000-0000-4000-8000-000000000001";
    expect(scrub({ a: `user_id=${id}`, b: [`account_id: ${id}`] })).toEqual({
      a: "user_id=[id:1]",
      b: ["account_id: [id:1]"],
    });
  });
});

describe("Error scrubbing", () => {
  it("scrubs message, stack, cause and own properties into a new Error of the same class", () => {
    class HttpError extends Error {
      status = 401;
      headers = { authorization: "Bearer x", accept: "json" };
      userEmail = "bob@example.com";
    }
    const cause = new TypeError("lookup failed for alice@example.com");
    const err = new HttpError("request failed token=abc123 for bob@example.com", { cause });
    const out = scrubError(err);
    expect(out).toBeInstanceOf(HttpError);
    expect(out).not.toBe(err);
    expect(out.message).toBe("request failed token=[redacted] for [email]");
    expect(out.stack).toContain("request failed token=[redacted] for [email]");
    expect(out.stack).not.toContain("bob@example.com");
    expect(out.stack?.split("\n").length).toBe(err.stack?.split("\n").length);
    expect(out.cause).toBeInstanceOf(TypeError);
    expect((out.cause as Error).message).toBe("lookup failed for [email]");
    expect(out.status).toBe(401);
    expect(out.headers).toEqual({ authorization: "[bearer-token]", accept: "json" });
    expect(out.userEmail).toBe("[email]");
    expect(Object.keys(out)).toEqual(Object.keys(err));
    // input untouched
    expect(err.message).toContain("bob@example.com");
    expect(err.userEmail).toBe("bob@example.com");
  });

  it("handles errors nested in objects, AggregateError and cyclic causes", () => {
    const a = new Error("a@b.co");
    const b = new Error("b", { cause: a });
    (a as { cause?: unknown }).cause = b;
    const agg = new AggregateError([new Error("c@d.io")], "many");
    const out = scrub({ err: b, agg });
    expect(out.err.cause).toBeInstanceOf(Error);
    expect((out.err.cause as Error).message).toBe("[email]");
    expect((out.err.cause as Error).cause).toBe("[circular]");
    expect((out.agg as AggregateError).errors[0].message).toBe("[email]");
  });

  it("scrubError passes non-errors through the normal value path", () => {
    expect(scrubError("x@y.io")).toBe("[email]");
    expect(scrubError(null)).toBe(null);
  });
});
