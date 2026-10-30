import { describe, expect, it } from "vitest";
import { scrubText } from "../src/index.js";

// Regression for 0.1.1: short Stripe-style keys were missed because the body required 16+ chars.
describe("Stripe short keys (0.1.1 regression)", () => {
  it.each([
    "sk_live_abc123XYZ456",
    "sk_test_abc123XYZ456",
    "rk_live_abc123XYZ456",
    "pk_test_abc123XYZ456",
    "whsec_abc123XYZ456",
    "sk_live_abcdefgh",
  ])("redacts %s", (key) => {
    expect(scrubText(`key=${key} end`)).not.toContain(key);
    expect(scrubText(`using ${key} now`)).toBe("using [api-key] now");
  });

  it.each([
    "the sk_live_ prefix marks live keys",
    "task_live_status",
    "mask_test_results_dir",
    "risk_live_feed",
    "sk_live_abc",
    "pk_test_1234567",
    "whsec_short",
    "my_sk_live_abcdefgh_value",
    "snake_case_words_live_test_value",
  ])("keeps %s", (text) => {
    expect(scrubText(text)).toBe(text);
  });

  it("stays linear on ~100 KB adversarial inputs", () => {
    const size = 100_000;
    const inputs = [
      "sk_live_".repeat(size / 8),
      `sk_live_${"a".repeat(size)}!`,
      "whsec_".repeat(size / 6),
      `${"_live_".repeat(size / 6)}x`,
      `whsec_${"a1".repeat(size / 2)}_`,
    ];
    for (const input of inputs) {
      const t = performance.now();
      scrubText(input);
      const ms = performance.now() - t;
      console.log(`stripe redos ${input.slice(0, 10)}… ${input.length} chars: ${ms.toFixed(1)} ms`);
      expect(ms).toBeLessThan(1500);
    }
  });
});
