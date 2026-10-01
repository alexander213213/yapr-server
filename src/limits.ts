// Transport and abuse limits (M1). Tunables via env with safe defaults.

/** Largest accepted NDJSON frame. Larger buffers destroy the socket (TOO_LARGE). */
export const MAX_FRAME_BYTES = Number(process.env.MAX_FRAME_BYTES ?? 64 * 1024);

/** Unauthenticated sockets must identify within this window or be destroyed. */
export const AUTH_TIMEOUT_MS = Number(process.env.AUTH_TIMEOUT_MS ?? 10_000);

/** Server heartbeat ping interval. */
export const PING_INTERVAL_MS = Number(process.env.PING_INTERVAL_MS ?? 30_000);

/** Sockets idle (no inbound frames) longer than this are destroyed. */
export const IDLE_TIMEOUT_MS = Number(process.env.IDLE_TIMEOUT_MS ?? 5 * 60_000);

/** Outbound kernel buffer ceiling; slower consumers are disconnected. */
export const MAX_WRITABLE_BYTES = Number(process.env.MAX_WRITABLE_BYTES ?? 256 * 1024);

/** Simple per-key token bucket. */
export class RateLimiter {
  private buckets = new Map<string, { tokens: number; resetAt: number }>();

  constructor(
    private readonly maxPerWindow: number,
    private readonly windowMs: number
  ) {}

  take(key: string, now = Date.now()): boolean {
    const current = this.buckets.get(key);
    if (!current || now >= current.resetAt) {
      this.buckets.set(key, { tokens: this.maxPerWindow - 1, resetAt: now + this.windowMs });
      return true;
    }
    if (current.tokens <= 0) return false;
    current.tokens -= 1;
    return true;
  }

  /** Drop expired buckets so the map can't grow unbounded. */
  sweep(now = Date.now()): void {
    for (const [key, bucket] of this.buckets) {
      if (now >= bucket.resetAt) this.buckets.delete(key);
    }
  }

  size(): number {
    return this.buckets.size;
  }
}

export const registerLimiter = new RateLimiter(
  Number(process.env.RATE_REGISTER_MAX ?? 10),
  Number(process.env.RATE_REGISTER_WINDOW_MS ?? 60_000)
);

export const sendLimiter = new RateLimiter(
  Number(process.env.RATE_SEND_MAX ?? 120),
  Number(process.env.RATE_SEND_WINDOW_MS ?? 60_000)
);
