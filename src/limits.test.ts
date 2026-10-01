import { describe, expect, it } from "vitest";
import { RateLimiter } from "./limits.js";

describe("RateLimiter", () => {
  it("allows up to the budget then rejects", () => {
    const limiter = new RateLimiter(2, 60_000);
    expect(limiter.take("ip", 0)).toBe(true);
    expect(limiter.take("ip", 1)).toBe(true);
    expect(limiter.take("ip", 2)).toBe(false);
  });

  it("resets after the window", () => {
    const limiter = new RateLimiter(1, 1000);
    expect(limiter.take("ip", 0)).toBe(true);
    expect(limiter.take("ip", 500)).toBe(false);
    expect(limiter.take("ip", 1000)).toBe(true);
  });

  it("tracks keys independently", () => {
    const limiter = new RateLimiter(1, 60_000);
    expect(limiter.take("a", 0)).toBe(true);
    expect(limiter.take("b", 0)).toBe(true);
  });

  it("sweep drops expired buckets", () => {
    const limiter = new RateLimiter(1, 1000);
    limiter.take("a", 0);
    expect(limiter.size()).toBe(1);
    limiter.sweep(2000);
    expect(limiter.size()).toBe(0);
  });
});
