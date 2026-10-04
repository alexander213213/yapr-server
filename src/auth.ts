import crypto, { randomUUID } from "node:crypto";

// scrypt parameters: interactive strength, ~10-30ms per hash. Registration and
// login are rate-limited, so sync hashing inside the handler is acceptable.
const N = 16384;
const R = 8;
const P = 1;
const KEY_LEN = 32;
const SALT_LEN = 16;

const DUMMY_SALT = Buffer.alloc(SALT_LEN, 0x59);

/** Stored form: `scrypt$N$r$p$saltHex$hashHex`. */
export function hashSecret(secret: string): string {
  const salt = crypto.randomBytes(SALT_LEN);
  const hash = crypto.scryptSync(secret, salt, KEY_LEN, { N, r: R, p: P });
  return `scrypt$${N}$${R}$${P}$${salt.toString("hex")}$${hash.toString("hex")}`;
}

/** Constant-time comparison against a stored hash. */
export function verifySecret(secret: string, stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, nStr, rStr, pStr, saltHex, hashHex] = parts;
  if (!nStr || !rStr || !pStr || !saltHex || !hashHex) return false;
  const n = Number(nStr);
  const r = Number(rStr);
  const p = Number(pStr);
  if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
  let salt: Buffer;
  let expected: Buffer;
  try {
    salt = Buffer.from(saltHex, "hex");
    expected = Buffer.from(hashHex, "hex");
  } catch {
    return false;
  }
  if (salt.length === 0 || expected.length === 0) return false;
  let actual: Buffer;
  try {
    actual = crypto.scryptSync(secret, salt, expected.length, { N: n, r, p });
  } catch {
    return false;
  }
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

/** Legacy v1 rows store the raw secret. Detect them for transparent re-hash. */
export function isLegacyPlaintextSecret(stored: string): boolean {
  return !stored.startsWith("scrypt$");
}

/**
 * Compare against a fixed dummy hash so unknown-user and wrong-secret logins
 * take the same code path and time (no account enumeration via timing).
 */
export function dummyCompare(secret: string): boolean {
  const dummy = crypto.scryptSync(secret, DUMMY_SALT, KEY_LEN, { N, r: R, p: P });
  const expected = crypto.scryptSync("dummy-never-matches", DUMMY_SALT, KEY_LEN, {
    N,
    r: R,
    p: P,
  });
  return crypto.timingSafeEqual(dummy, expected);
}

export function generateSecret(): string {
  return crypto.randomBytes(32).toString("hex");
}

export function generateMessageId(): string {
  return randomUUID();
}

export function generateGroupId(): string {
  return `grp_${randomUUID()}`;
}

const MIN_USER_ID = 100_000_000_000;
const MAX_USER_ID = 1_000_000_000_000;
const MAX_ATTEMPTS = 10;

export function generateUserId(exists: (id: string) => boolean): string {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const id = crypto.randomInt(MIN_USER_ID, MAX_USER_ID).toString();
    if (!exists(id)) return id;
  }
  throw new Error("user id allocation failed after retries");
}
