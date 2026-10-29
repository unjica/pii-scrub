import { describe, expect, it } from "vitest";
import { createScrubber, passesLuhn, scrubText } from "../src/index.js";

/** Ordinary log text that must pass through the default scrubber unchanged. */
const CORPUS = [
  "TypeError: Cannot read property 'x' of undefined",
  "    at Object.<anonymous> (/usr/local/lib/node_modules/app/index.js:10:5)",
  "Error:   boom\t\there",
  // versions
  "v1.2.3",
  "node 22.11.0 / npm 10.9.0",
  "react@18.3.1 and @scope/pkg@1.0.0-beta.2",
  "Windows 10.0.19041.1",
  "build 1.2.3.4",
  "ref 123.456.7890",
  // timestamps and durations
  "2026-10-29T19:01:41.679Z",
  "2026-10-29 20:01:41 +01:00",
  "at 12:30:45.123",
  "epoch 1761764501 / 1730000000000 / 1761764501123",
  "20260716123000",
  "took 1234567890123ns",
  // identifiers
  "trace b0000000-0000-4000-8000-000000000002",
  "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
  "commit 4b825dc642cb6eb9a060e54bf8d69288fbee4904",
  "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "order 5551234567",
  "2025550183",
  "1234567890",
  "id 4111111111111112",
  "4242424242424241",
  "ISBN 978-3-16-148410-0",
  "SKU AB12 CDEF GHIJ KLMN",
  "DE00 3704 0044 0532 0130 00",
  // prose that mentions secrets without containing one
  "Missing Bearer token in request",
  "password reset requested",
  "session expired, please re-authenticate",
  "auth failed: invalid credentials",
  "token refresh scheduled",
  "set cookie banner preference",
  // network-ish text (IP detection is opt-in)
  "listening on localhost:3000",
  "connect 127.0.0.1:5432",
  "https://example.com/docs/getting-started#install",
  "see https://x.io/a, ok?",
  // money and quantities
  "total €1,234.56 (EUR) for 3 items",
  "HTTP 404 Content-Length: 12345",
  "score +15 points",
  "SGVsbG8gd29ybGQ=",
  "unicode žćčšđ 你好 🙂",
];

describe("false positives (default detectors)", () => {
  it.each(CORPUS)("keeps %j intact", (line) => {
    expect(scrubText(line)).toBe(line);
  });

  it("keeps UUIDs whose digit groups happen to pass Luhn", () => {
    // Construct a UUID whose first three groups are all digits, start with 4 and pass Luhn.
    let found: string | undefined;
    for (let i = 0; i < 1_000_000 && !found; i++) {
      const digits = `4${String(i).padStart(15, "0")}`;
      if (passesLuhn(digits)) found = digits;
    }
    expect(found).toBeDefined();
    const d = found as string;
    const uuid = `${d.slice(0, 8)}-${d.slice(8, 12)}-${d.slice(12, 16)}-8000-000000000000`;
    expect(scrubText(`request ${uuid}`)).toBe(`request ${uuid}`);
  });

  it("keeps version-like dotted quads even with IPv4 detection on when prefixed with v", () => {
    const s = createScrubber({ detectors: { ipv4: true, ipv6: true } });
    expect(s.text("v1.2.3.4")).toBe("v1.2.3.4");
    expect(s.text("at 12:30:45")).toBe("at 12:30:45");
    expect(s.text("std::vector and a::b")).toBe("std::vector and a::b");
    expect(s.text("mac 00:1A:2B:3C:4D:5E")).toBe("mac 00:1A:2B:3C:4D:5E");
  });

  it("leaves non-sensitive structured payloads equal", () => {
    const payload = {
      level: "info",
      msg: "GET /orders 200",
      durationMs: 12.5,
      ts: "2026-10-29T19:01:41.679Z",
      version: "1.4.2",
      traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
      requestId: "b0000000-0000-4000-8000-000000000002",
      tags: ["checkout", "eu-west-1"],
    };
    expect(createScrubber().value(payload)).toEqual(payload);
  });
});
