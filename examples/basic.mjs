// Run after `npm run build`: node examples/basic.mjs
import { createScrubber, scrub, scrubError, scrubText } from "../dist/index.js";

console.log(scrubText("Payment failed for jane@example.com, card 4111 1111 1111 1111"));

console.log(scrub({ user: { email: "jane@example.com", password: "hunter2" }, plan: "pro" }));

const err = scrubError(new Error("lookup failed for jane@example.com"));
console.log(err.message);

const scrubber = createScrubber({
  detectors: { phone: false },
  customDetectors: [{ name: "orderId", pattern: /\bORD-\d{6}\b/g, replacement: "[order]" }],
});
console.log(scrubber.text("order ORD-123456 for +386 40 123 456"));
