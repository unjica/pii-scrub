/** Luhn (mod 10) check for payment-card digit strings of 13–19 digits. */
export function passesLuhn(digits: string): boolean {
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/** IBAN length per ISO 3166 country code (SWIFT IBAN registry). */
const IBAN_LENGTHS: Readonly<Record<string, number>> = {
  AD: 24,
  AE: 23,
  AL: 28,
  AT: 20,
  AZ: 28,
  BA: 20,
  BE: 16,
  BG: 22,
  BH: 22,
  BI: 27,
  BR: 29,
  BY: 28,
  CH: 21,
  CR: 22,
  CY: 28,
  CZ: 24,
  DE: 22,
  DJ: 27,
  DK: 18,
  DO: 28,
  EE: 20,
  EG: 29,
  ES: 24,
  FI: 18,
  FK: 18,
  FO: 18,
  FR: 27,
  GB: 22,
  GE: 22,
  GI: 23,
  GL: 18,
  GR: 27,
  GT: 28,
  HN: 28,
  HR: 21,
  HU: 28,
  IE: 22,
  IL: 23,
  IQ: 23,
  IS: 26,
  IT: 27,
  JO: 30,
  KW: 30,
  KZ: 20,
  LB: 28,
  LC: 32,
  LI: 21,
  LT: 20,
  LU: 20,
  LV: 21,
  LY: 25,
  MC: 27,
  MD: 24,
  ME: 22,
  MK: 19,
  MN: 20,
  MR: 27,
  MT: 31,
  MU: 30,
  NI: 28,
  NL: 18,
  NO: 15,
  OM: 23,
  PK: 24,
  PL: 28,
  PS: 29,
  PT: 25,
  QA: 29,
  RO: 24,
  RS: 22,
  RU: 33,
  SA: 24,
  SC: 31,
  SD: 18,
  SE: 24,
  SI: 19,
  SK: 24,
  SM: 27,
  SO: 23,
  ST: 25,
  SV: 28,
  TL: 23,
  TN: 24,
  TR: 26,
  UA: 29,
  VA: 22,
  VG: 24,
  XK: 20,
  YE: 30,
};

/** Expected IBAN length for a country code, or undefined if unknown. */
export function ibanLength(countryCode: string): number | undefined {
  return IBAN_LENGTHS[countryCode];
}

/** Validates a compact (no spaces), upper-case IBAN: known country, length and mod-97 checksum. */
export function isValidIban(compact: string): boolean {
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(compact)) return false;
  const expected = IBAN_LENGTHS[compact.slice(0, 2)];
  if (expected === undefined || compact.length !== expected) return false;
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    const value = code >= 65 ? code - 55 : code - 48;
    remainder = value >= 10 ? (remainder * 100 + value) % 97 : (remainder * 10 + value) % 97;
  }
  return remainder === 1;
}

/** Strict dotted-quad IPv4 check (no leading zeros except "0"). */
export function isValidIpv4(candidate: string): boolean {
  const parts = candidate.split(".");
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255) return false;
  }
  return true;
}

/** IPv6 check (RFC 4291 text forms, incl. "::" compression and embedded IPv4). */
export function isValidIpv6(candidate: string): boolean {
  if (candidate.length < 2 || candidate.length > 45) return false;
  let text = candidate;
  const groupsBudget = 8;
  const lastColon = text.lastIndexOf(":");
  const tail = text.slice(lastColon + 1);
  if (tail.includes(".")) {
    if (!isValidIpv4(tail)) return false;
    text = `${text.slice(0, lastColon + 1)}0:0`;
  }
  const doubleColon = text.indexOf("::");
  if (doubleColon !== text.lastIndexOf("::")) return false;
  const hexGroup = /^[0-9a-fA-F]{1,4}$/;
  if (doubleColon === -1) {
    const groups = text.split(":");
    return groups.length === groupsBudget && groups.every((g) => hexGroup.test(g));
  }
  const head = text.slice(0, doubleColon);
  const rest = text.slice(doubleColon + 2);
  const headGroups = head === "" ? [] : head.split(":");
  const restGroups = rest === "" ? [] : rest.split(":");
  if (![...headGroups, ...restGroups].every((g) => hexGroup.test(g))) return false;
  const explicit = [...headGroups, ...restGroups];
  if (explicit.length > groupsBudget - 1) return false;
  // Skip "::", "::1" and code-like tokens such as "a::b": require 3+ groups or a full 4-digit group.
  return explicit.length >= 3 || (explicit.length === 2 && explicit.some((g) => g.length === 4));
}
