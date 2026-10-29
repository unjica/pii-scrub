import { describe, expect, it } from "vitest";
import {
  createScrubber,
  isValidIban,
  isValidIpv4,
  isValidIpv6,
  passesLuhn,
  scrubText,
} from "../src/index.js";

describe("built-in text detectors", () => {
  it("email", () => {
    expect(scrubText("Failed for user@example.com")).toBe("Failed for [email]");
    expect(scrubText("a.b+tag@sub.example.co.uk, c@d.io")).toBe("[email], [email]");
  });

  it("jwt", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature";
    expect(scrubText(`Token ${jwt}`)).toBe("Token [token]");
  });

  it("bearer tokens, but not prose", () => {
    expect(scrubText("Authorization Bearer abc.def-ghi_123")).toBe("Authorization [bearer-token]");
    expect(scrubText("bearer 0123456789abcdef")).toBe("[bearer-token]");
    expect(scrubText("Missing Bearer token in request")).toBe("Missing Bearer token in request");
  });

  it("well-known API key formats", () => {
    const keys = [
      "sk-abcdefghijklmnopqrstuvwxyz",
      "sk-proj-Ab3dEf6hIj9kLmNoPq",
      "pk-ABCDEFGHIJKLMNOP1234",
      "sk_live_51HxAbCdEfGhIjKlMn",
      "rk_test_51HxAbCdEfGhIjKlMn",
      "whsec_AbCdEfGhIjKlMnOpQr",
      `ghp_${"a1".repeat(18)}`,
      `github_pat_${"A_1b".repeat(6)}`,
      "glpat-abcdefghij0123456789",
      "xoxb-123456789012-abcdefghij",
      "AKIAIOSFODNN7EXAMPLE",
      `AIza${"x".repeat(35)}`,
      `npm_${"a".repeat(36)}`,
    ];
    for (const k of keys) expect(scrubText(`key ${k} end`), k).toBe("key [api-key] end");
  });

  it("does not ship product-specific key formats", () => {
    expect(scrubText("tt_live_abcd0123efgh4567_secretpart")).toBe("tt_live_abcd0123efgh4567_secretpart");
  });

  it("IBAN with checksum validation", () => {
    expect(scrubText("pay DE89 3704 0044 0532 0130 00 now")).toBe("pay [iban] now");
    expect(scrubText("SI56263300012039086")).toBe("[iban]");
    expect(scrubText("GB82WEST12345698765432")).toBe("[iban]");
    expect(scrubText("DE89 3704 0044 0532 0130 00 EUR")).toBe("[iban] EUR");
    // bad checksum
    expect(scrubText("DE00 3704 0044 0532 0130 00")).toBe("DE00 3704 0044 0532 0130 00");
  });

  it("Luhn-valid card numbers", () => {
    expect(scrubText("card 4111 1111 1111 1111 charged")).toBe("card [card] charged");
    expect(scrubText("pan=4111111111111111")).toBe("pan=[card]");
    expect(scrubText("4242-4242-4242-4242")).toBe("[card]");
    expect(scrubText("amex 3782 822463 10005")).toBe("amex [card]");
    expect(scrubText("mc 5555555555554444")).toBe("mc [card]");
  });

  it("phone numbers (E.164 and formatted NANP)", () => {
    expect(scrubText("call +15551234567")).toBe("call [phone]");
    expect(scrubText("call (555) 123-4567")).toBe("call [phone]");
    expect(scrubText("+386 40 123 456")).toBe("[phone]");
    expect(scrubText("+1-202-555-0183")).toBe("[phone]");
    expect(scrubText("+1 (202) 555-0183")).toBe("[phone]");
  });

  it("IP addresses are opt-in", () => {
    const s = createScrubber({ detectors: { ipv4: true, ipv6: true } });
    expect(scrubText("from 203.0.113.7")).toBe("from 203.0.113.7");
    expect(s.text("from 203.0.113.7.")).toBe("from [ip].");
    expect(s.text("from 2001:db8:85a3::8a2e:370:7334")).toBe("from [ip]");
    expect(s.text("[2001:db8::1]:443")).toBe("[[ip]]:443");
    expect(s.text("::ffff:192.0.2.128")).toBe("[ip]");
    expect(s.text("fe80:0:0:0:200:f8ff:fe21:67cf")).toBe("[ip]");
    expect(s.text("999.1.1.1 and 1.2.3")).toBe("999.1.1.1 and 1.2.3");
  });

  it("secret query parameters, assignments and JSON fields", () => {
    expect(scrubText("/cb?code=1&access_token=abc&x=1")).toBe("/cb?code=1&access_token=[redacted]&x=1");
    expect(scrubText("Failed with token=abc123")).toBe("Failed with token=[redacted]");
    expect(scrubText("password = hunter2 next")).toBe("password=[redacted] next");
    expect(scrubText("client_secret=abc")).toBe("client_secret=[redacted]");
    expect(scrubText('{"password":"hunter2","user":"x"}')).toBe('{"password":"[redacted]","user":"x"}');
    expect(scrubText('{"apiKey": "a\\"b"}')).toBe('{"apiKey": "[redacted]"}');
  });

  it("cookie and authorization headers, keeping header case and newlines", () => {
    expect(scrubText("cookie: session=abc123")).toBe("cookie: [cookie]");
    expect(scrubText("Set-Cookie: a=b; HttpOnly\nnext")).toBe("Set-Cookie: [cookie]\nnext");
    expect(scrubText("authorization: Bearer secret")).toBe("authorization: [bearer-token]");
    expect(scrubText("Authorization: Basic dXNlcjpwYXNz\nHost: x")).toBe(
      "Authorization: [bearer-token]\nHost: x",
    );
  });

  it("URL query strings are stripped, fragments kept unless the query is sensitive", () => {
    expect(scrubText("GET https://api.example.com/orders?id=123")).toBe("GET https://api.example.com/orders");
    expect(scrubText("https://x.io/a?q=1#frag")).toBe("https://x.io/a#frag");
    expect(scrubText("https://api.example.com/auth?token=abc123#x")).toBe("https://api.example.com/auth");
    expect(scrubText("see https://x.io/a, ok?")).toBe("see https://x.io/a, ok?");
  });

  it("UUIDs only in user/session/account context, with stable correlation ids per call", () => {
    const a = "a0000000-0000-4000-8000-000000000001";
    const b = "b0000000-0000-4000-8000-000000000002";
    expect(scrubText(`user_id=${a} session-id: ${b} userId=${a.toUpperCase()}`)).toBe(
      "user_id=[id:1] session-id: [id:2] userId=[id:1]",
    );
    expect(scrubText(`trace ${b}`)).toBe(`trace ${b}`);
  });

  it("keeps newlines and whitespace", () => {
    const stack = "Error: mail user@example.com\n    at run (entry.js:10:2)";
    expect(scrubText(stack)).toBe("Error: mail [email]\n    at run (entry.js:10:2)");
    expect(scrubText("Error:   boom\t\there")).toBe("Error:   boom\t\there");
  });

  it("returns non-strings unchanged from text()", () => {
    expect(createScrubber().text(42 as unknown as string)).toBe(42);
  });
});

describe("configuration", () => {
  it("disables built-in detectors", () => {
    const s = createScrubber({ detectors: { email: false, urlQuery: false } });
    expect(s.text("a@b.co https://x.io/?q=1")).toBe("a@b.co https://x.io/?q=1");
  });

  it("rejects unknown detector names", () => {
    expect(() => createScrubber({ detectors: { nope: true } as never })).toThrow(/unknown detector/);
  });

  it("custom detectors run first, support validate and replacement functions", () => {
    const s = createScrubber({
      customDetectors: [
        { name: "orderRef", pattern: /\bORD-\d{6}\b/, replacement: "[order]" },
        { name: "even", pattern: /\bN\d+\b/g, validate: (m) => Number(m.slice(1)) % 2 === 0 },
        { name: "fn", pattern: /\bacct_\w{4}\b/g, replacement: (m) => `[acct:${m.length}]` },
        { name: "literal", pattern: /\bX1\b/g, replacement: "$&-not-expanded" },
      ],
    });
    expect(s.text("ORD-123456 ORD-123456 N2 N3 acct_abcd X1")).toBe(
      "[order] [order] [redacted] N3 [acct:9] $&-not-expanded",
    );
  });

  it("validates custom detector shape", () => {
    expect(() => createScrubber({ customDetectors: [{ name: "x", pattern: "x" as never }] })).toThrow(
      TypeError,
    );
  });

  it("custom placeholders", () => {
    const s = createScrubber({ placeholders: { email: "<EMAIL>", id: "<user #{n}>" } });
    expect(s.text("x@y.io user_id=a0000000-0000-4000-8000-000000000001")).toBe("<EMAIL> user_id=<user #1>");
    expect(s.value({ email: "x" })).toEqual({ email: "<EMAIL>" });
  });

  it("custom secret names and context id names", () => {
    const s = createScrubber({ secretNames: ["pin"], contextIdNames: ["tenant_id"] });
    expect(s.text("pin=1234 token=abc tenant_id=a0000000-0000-4000-8000-000000000001")).toBe(
      "pin=[redacted] token=abc tenant_id=[id:1]",
    );
    expect(createScrubber({ secretNames: [] }).text("token=abc")).toBe("token=abc");
  });

  it("validates limits", () => {
    expect(() => createScrubber({ maxDepth: -1 })).toThrow(RangeError);
  });
});

describe("validators", () => {
  it("passesLuhn", () => {
    expect(passesLuhn("4111111111111111")).toBe(true);
    expect(passesLuhn("4111111111111112")).toBe(false);
    expect(passesLuhn("12")).toBe(false);
  });
  it("isValidIban", () => {
    expect(isValidIban("DE89370400440532013000")).toBe(true);
    expect(isValidIban("DE8937040044053201300")).toBe(false);
    expect(isValidIban("ZZ89370400440532013000")).toBe(false);
  });
  it("isValidIpv4 / isValidIpv6", () => {
    expect(isValidIpv4("10.0.0.1")).toBe(true);
    expect(isValidIpv4("01.0.0.1")).toBe(false);
    expect(isValidIpv6("2001:db8::1")).toBe(true);
    expect(isValidIpv6("::1")).toBe(false);
    expect(isValidIpv6("1:2:3:4:5:6:7:8")).toBe(true);
    expect(isValidIpv6("1:2:3:4:5:6:7:8:9")).toBe(false);
    expect(isValidIpv6("1::2::3")).toBe(false);
    expect(isValidIpv6("12:30:45")).toBe(false);
  });
});

describe("card detection inside longer digit runs", () => {
  it("finds a card next to unrelated numbers", () => {
    expect(scrubText("qty 9 4782292877401173) x")).toBe("qty 9 [card]) x");
    expect(scrubText("1234 4111 1111 1111 1111")).toBe("1234 [card]");
    expect(scrubText("4111 1111 1111 1111 9")).toBe("[card] 9");
    expect(scrubText("4111111111111111 4242 4242 4242 4242")).toBe("[card] [card]");
  });
  it("does not split contiguous digit runs", () => {
    expect(scrubText("41111111111111119")).toBe("41111111111111119");
  });
});
