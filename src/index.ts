import { createScrubber, DEFAULT_PLACEHOLDERS, DEFAULT_SENSITIVE_KEYS } from "./scrubber.js";
import type { Scrubber, ScrubOptions } from "./types.js";

export {
  BUILT_IN_DETECTORS,
  DEFAULT_CONTEXT_ID_NAMES,
  DEFAULT_SECRET_NAMES,
} from "./detectors.js";
export type {
  BuiltInDetectorName,
  CustomDetector,
  Placeholders,
  Scrubber,
  ScrubOptions,
} from "./types.js";
export { isValidIban, isValidIpv4, isValidIpv6, passesLuhn } from "./validators.js";
export { createScrubber, DEFAULT_PLACEHOLDERS, DEFAULT_SENSITIVE_KEYS };

let defaultScrubber: Scrubber | undefined;
function getDefault(options?: ScrubOptions): Scrubber {
  if (options) return createScrubber(options);
  defaultScrubber ??= createScrubber();
  return defaultScrubber;
}

/** Scrub free-form text with the default (or given) options. */
export function scrubText(input: string, options?: ScrubOptions): string {
  return getDefault(options).text(input);
}

/** Deep-scrub any value with the default (or given) options. Never mutates the input. */
export function scrub<T>(input: T, options?: ScrubOptions): T {
  return getDefault(options).value(input);
}

/** Scrub an Error into a new Error with the same prototype; message, stack, cause and own properties are scrubbed. */
export function scrubError<T>(input: T, options?: ScrubOptions): T {
  return getDefault(options).error(input);
}
