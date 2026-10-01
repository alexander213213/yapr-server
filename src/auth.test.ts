import { describe, expect, it } from "vitest";
import {
  dummyCompare,
  generateUserId,
  hashSecret,
  isLegacyPlaintextSecret,
  verifySecret,
} from "./auth.js";

describe("secret hashing", () => {
  it("round-trips a correct secret", () => {
    const stored = hashSecret("correct horse");
    expect(verifySecret("correct horse", stored)).toBe(true);
  });

  it("rejects a wrong secret", () => {
    const stored = hashSecret("correct horse");
    expect(verifySecret("wrong donkey", stored)).toBe(false);
  });

  it("rejects garbage stored values without throwing", () => {
    expect(verifySecret("x", "not-a-hash")).toBe(false);
    expect(verifySecret("x", "scrypt$bad")).toBe(false);
  });

  it("detects legacy plaintext rows", () => {
    expect(isLegacyPlaintextSecret("deadbeef")).toBe(true);
    expect(isLegacyPlaintextSecret(hashSecret("x"))).toBe(false);
  });

  it("dummy compare runs without matching", () => {
    expect(dummyCompare("anything")).toBe(false);
  });
});

describe("generateUserId", () => {
  it("returns a 12-digit id not in use", () => {
    const id = generateUserId(() => false);
    expect(id).toMatch(/^\d{12}$/);
  });

  it("throws after bounded retries when exhausted", () => {
    expect(() => generateUserId(() => true)).toThrow();
  });
});
