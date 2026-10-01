import { describe, expect, it } from "vitest";
import { isErrorMessage, parseFrame } from "./protocol.js";

describe("parseFrame", () => {
  it("parses a valid register frame", () => {
    const msg = parseFrame(`{"type":"register"}`);
    expect(isErrorMessage(msg)).toBe(false);
    expect(msg).toEqual({ type: "register" });
  });

  it("parses a valid send frame", () => {
    const msg = parseFrame(
      `{"type":"send_message","clientMessageId":"a","to":"123","text":"hi"}`
    );
    expect(msg).toMatchObject({ type: "send_message", to: "123" });
  });

  it("parses pong", () => {
    expect(parseFrame(`{"type":"pong"}`)).toEqual({ type: "pong" });
  });

  it("rejects malformed JSON with INVALID", () => {
    const msg = parseFrame(`{nope`);
    expect(isErrorMessage(msg)).toBe(true);
    if (isErrorMessage(msg)) expect(msg.code).toBe("INVALID");
  });

  it("rejects unknown types with INVALID", () => {
    const msg = parseFrame(`{"type":"nuke"}`);
    expect(isErrorMessage(msg)).toBe(true);
  });

  it("rejects missing fields with INVALID", () => {
    const msg = parseFrame(`{"type":"identify","userId":"1"}`);
    expect(isErrorMessage(msg)).toBe(true);
  });

  it("rejects oversize text with INVALID", () => {
    const big = "x".repeat(8193);
    const msg = parseFrame(
      JSON.stringify({ type: "send_message", clientMessageId: "a", to: "1", text: big })
    );
    expect(isErrorMessage(msg)).toBe(true);
  });
});
