import crypto from "node:crypto";

// Account-recovery tokens: server-sealed bearer envelopes carrying only the
// user id (`{ v: 1, userId }`). Only a server holding YAPR_RECLAIM_KEY can
// mint or open them. The token alone re-creates the account row with a FRESH
// secret (returned to the claimer, who must then identify normally), so a
// leaked token is password-equivalent: guard it like a credential.
// Deliberately minimal: no audience (key-scoped), no expiry (rotation is via
// re-minting on identify). Group memberships are never restored from tokens
// (a stale token must not re-admit a removed member).

const RECLAIM_INFO = "yapr-reclaim-v1";
const GCM_NONCE_LEN = 12;
const GCM_TAG_LEN = 16;
const TOKEN_VERSION = 1;

/** Load the 32-byte reclaim key from env. Null = feature off (no crash). */
export function getReclaimKey(): Buffer | null {
  const raw = process.env.YAPR_RECLAIM_KEY?.trim();
  if (!raw) return null;
  try {
    const key = Buffer.from(raw, "base64");
    if (key.length !== 32) return null;
    return key;
  } catch {
    return null;
  }
}

function subKey(master: Buffer): Buffer {
  return Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(0), RECLAIM_INFO, 32));
}

/** Seal a user id into an opaque base64 token. */
export function mintReclaimToken(masterKey: Buffer, userId: string): string {
  const nonce = crypto.randomBytes(GCM_NONCE_LEN);
  const cipher = crypto.createCipheriv("aes-256-gcm", subKey(masterKey), nonce);
  const payload = JSON.stringify({ v: TOKEN_VERSION, userId });
  const sealed = Buffer.concat([
    cipher.update(payload, "utf8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return Buffer.concat([nonce, sealed]).toString("base64");
}

/** Open a token. Returns the user id, or null for any failure (never throws). */
export function verifyReclaimToken(masterKey: Buffer, token: string): string | null {
  try {
    const raw = Buffer.from(token, "base64");
    if (raw.length < GCM_NONCE_LEN + GCM_TAG_LEN + 1) return null;
    const nonce = raw.subarray(0, GCM_NONCE_LEN);
    const sealed = raw.subarray(GCM_NONCE_LEN);
    const decipher = crypto.createDecipheriv("aes-256-gcm", subKey(masterKey), nonce);
    decipher.setAuthTag(sealed.subarray(sealed.length - GCM_TAG_LEN));
    const plaintext = Buffer.concat([
      decipher.update(sealed.subarray(0, sealed.length - GCM_TAG_LEN)),
      decipher.final(),
    ]).toString("utf8");
    const obj: unknown = JSON.parse(plaintext);
    if (typeof obj !== "object" || obj === null) return null;
    const { v, userId } = obj as { v?: unknown; userId?: unknown };
    if (v !== TOKEN_VERSION || typeof userId !== "string") return null;
    if (userId.length < 1 || userId.length > 64) return null;
    return userId;
  } catch {
    return null;
  }
}
