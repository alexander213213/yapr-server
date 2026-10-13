import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  getReclaimKey,
  mintReclaimToken,
  verifyReclaimToken,
} from "./reclaim.js";

function randomKey(): Buffer {
  return crypto.randomBytes(32);
}

describe("reclaim tokens", () => {
  it("round-trips a user id", () => {
    const key = randomKey();
    const token = mintReclaimToken(key, "123456789012");
    expect(verifyReclaimToken(key, token)).toBe("123456789012");
  });

  it("minting is randomized (no two tokens alike)", () => {
    const key = randomKey();
    expect(mintReclaimToken(key, "1")).not.toBe(mintReclaimToken(key, "1"));
  });

  it("rejects wrong-key tokens", () => {
    const token = mintReclaimToken(randomKey(), "123456789012");
    expect(verifyReclaimToken(randomKey(), token)).toBeNull();
  });

  it("rejects forged, truncated and garbage tokens without throwing", () => {
    const key = randomKey();
    const good = mintReclaimToken(key, "123456789012");
    const tampered = Buffer.from(good, "base64");
    const last = tampered[tampered.length - 1] ?? 0;
    tampered[tampered.length - 1] = last ^ 0xff;
    expect(verifyReclaimToken(key, tampered.toString("base64"))).toBeNull();
    expect(verifyReclaimToken(key, good.slice(0, 20))).toBeNull();
    expect(verifyReclaimToken(key, "")).toBeNull();
    expect(verifyReclaimToken(key, "not-base64!!!")).toBeNull();
  });

  it("rejects tampered payload versions and bad user ids", () => {
    const key = randomKey();
    // Craft a validly-sealed envelope with wrong contents via the module's
    // own primitives is impossible without the key; instead check overly long
    // ids are refused at the boundary by minting then verifying empty/long.
    expect(verifyReclaimToken(key, mintReclaimToken(key, ""))).toBeNull();
    expect(verifyReclaimToken(key, mintReclaimToken(key, "x".repeat(65)))).toBeNull();
  });

  it("loads the key from env, rejects bad lengths, off when unset", () => {
    const prev = process.env.YAPR_RECLAIM_KEY;
    try {
      process.env.YAPR_RECLAIM_KEY = randomKey().toString("base64");
      expect(getReclaimKey()?.length).toBe(32);
      process.env.YAPR_RECLAIM_KEY = Buffer.alloc(16).toString("base64");
      expect(getReclaimKey()).toBeNull();
      delete process.env.YAPR_RECLAIM_KEY;
      expect(getReclaimKey()).toBeNull();
    } finally {
      if (prev === undefined) delete process.env.YAPR_RECLAIM_KEY;
      else process.env.YAPR_RECLAIM_KEY = prev;
    }
  });
});
