import { describe, expect, it } from "vitest";
import { isErrorMessage, parseFrame } from "./protocol.js";

const V = `"v":2`;

describe("parseFrame (v2)", () => {
  it("parses a valid register frame with pubKey", () => {
    const msg = parseFrame(`{${V},"type":"register","pubKey":"cHVia2V5"}`);
    expect(isErrorMessage(msg)).toBe(false);
    expect(msg).toEqual({ v: 2, type: "register", pubKey: "cHVia2V5" });
  });

  it("parses a valid opaque send frame", () => {
    const msg = parseFrame(
      `{${V},"type":"send","clientMessageId":"a","to":"123","ciphertext":"Y2lwaGVy","nonce":"bm9uY2U=","timestamp":123}`
    );
    expect(msg).toMatchObject({ v: 2, type: "send", to: "123" });
  });

  it("parses fetch_keys, ack, read, fetch_pending and pong", () => {
    expect(parseFrame(`{${V},"type":"fetch_keys","userIds":["1","2"]}`)).toMatchObject({
      type: "fetch_keys",
    });
    expect(parseFrame(`{${V},"type":"ack","messageId":"m"}`)).toMatchObject({ type: "ack" });
    expect(parseFrame(`{${V},"type":"read","messageId":"m"}`)).toMatchObject({ type: "read" });
    expect(parseFrame(`{${V},"type":"fetch_pending","limit":10}`)).toMatchObject({
      type: "fetch_pending",
    });
    expect(parseFrame(`{${V},"type":"pong"}`)).toEqual({ v: 2, type: "pong" });
  });

  it("rejects v1 frames without a version as UPGRADE_REQUIRED", () => {
    const legacy = parseFrame(`{"type":"register"}`);
    expect(isErrorMessage(legacy)).toBe(true);
    if (isErrorMessage(legacy)) expect(legacy.code).toBe("UPGRADE_REQUIRED");
  });

  it("rejects wrong versions as UPGRADE_REQUIRED", () => {
    const msg = parseFrame(`{"v":1,"type":"register","pubKey":"x"}`);
    expect(isErrorMessage(msg)).toBe(true);
    if (isErrorMessage(msg)) expect(msg.code).toBe("UPGRADE_REQUIRED");
  });

  it("rejects malformed JSON with INVALID", () => {
    const msg = parseFrame(`{nope`);
    expect(isErrorMessage(msg)).toBe(true);
    if (isErrorMessage(msg)) expect(msg.code).toBe("INVALID");
  });

  it("rejects unknown types with INVALID", () => {
    const msg = parseFrame(`{${V},"type":"nuke"}`);
    expect(isErrorMessage(msg)).toBe(true);
    if (isErrorMessage(msg)) expect(msg.code).toBe("INVALID");
  });

  it("rejects missing fields with INVALID", () => {
    const msg = parseFrame(`{${V},"type":"identify","userId":"1"}`);
    expect(isErrorMessage(msg)).toBe(true);
  });

  it("rejects oversize ciphertext with INVALID", () => {
    const big = "x".repeat(32 * 1024 + 1);
    const msg = parseFrame(
      JSON.stringify({
        v: 2,
        type: "send",
        clientMessageId: "a",
        to: "1",
        ciphertext: big,
        nonce: "n",
        timestamp: 1,
      })
    );
    expect(isErrorMessage(msg)).toBe(true);
  });

  it("rejects oversize fetch_keys batches with INVALID", () => {
    const msg = parseFrame(
      JSON.stringify({ v: 2, type: "fetch_keys", userIds: Array(51).fill("x") })
    );
    expect(isErrorMessage(msg)).toBe(true);
  });
});
