import { z } from "zod";

/** Protocol version. Every frame carries `v: 2`; anything else is rejected
 *  with UPGRADE_REQUIRED so old clients get an actionable signal. */
export const PROTOCOL_VERSION = 2 as const;

/** Machine-readable error codes. `message` stays human-friendly but generic
 *  (no user enumeration: unknown user and wrong secret both yield UNAUTH). */
export const ErrorCode = z.enum([
  "INVALID",
  "UNAUTH",
  "NOT_FOUND",
  "RATE_LIMITED",
  "TOO_LARGE",
  "UPGRADE_REQUIRED",
]);
export type ErrorCode = z.infer<typeof ErrorCode>;

const v = z.literal(PROTOCOL_VERSION);
const userIdField = z.string().min(1).max(64);
const secretField = z.string().min(1).max(256);
const messageIdField = z.string().min(1).max(128);
// Opaque E2EE envelope: base64 ciphertext (32KB cap) + base64 nonce.
const ciphertextField = z.string().min(1).max(32 * 1024);
const nonceField = z.string().max(128);
// X25519 public key, base64 (32 bytes -> 44 chars); room for future key types.
const pubKeyField = z.string().min(1).max(128);

export const RegisterMessage = z.object({
  v,
  type: z.literal("register"),
  pubKey: pubKeyField,
});
export type RegisterMessage = z.infer<typeof RegisterMessage>;

export const IdentifyMessage = z.object({
  v,
  type: z.literal("identify"),
  userId: userIdField,
  secret: secretField,
});
export type IdentifyMessage = z.infer<typeof IdentifyMessage>;

export const FetchKeysMessage = z.object({
  v,
  type: z.literal("fetch_keys"),
  userIds: z.array(userIdField).min(1).max(50),
});
export type FetchKeysMessage = z.infer<typeof FetchKeysMessage>;

export const SendMessage = z.object({
  v,
  type: z.literal("send"),
  clientMessageId: z.string().min(1).max(128),
  to: userIdField,
  ciphertext: ciphertextField,
  nonce: nonceField,
  timestamp: z.number().int().nonnegative(),
});
export type SendMessage = z.infer<typeof SendMessage>;

export const AckMessage = z.object({
  v,
  type: z.literal("ack"),
  messageId: messageIdField,
});
export type AckMessage = z.infer<typeof AckMessage>;

export const ReadMessage = z.object({
  v,
  type: z.literal("read"),
  messageId: messageIdField,
});
export type ReadMessage = z.infer<typeof ReadMessage>;

export const FetchPendingMessage = z.object({
  v,
  type: z.literal("fetch_pending"),
  cursor: z
    .object({
      createdAt: z.number().int().nonnegative(),
      messageId: messageIdField,
    })
    .optional(),
  limit: z.number().int().min(1).max(200).optional(),
});
export type FetchPendingMessage = z.infer<typeof FetchPendingMessage>;

/** Heartbeat reply from clients (server sends `{ v: 2, type: "ping" }`). */
export const PongMessage = z.object({
  v,
  type: z.literal("pong"),
});
export type PongMessage = z.infer<typeof PongMessage>;

export const ClientMessage = z.discriminatedUnion("type", [
  RegisterMessage,
  IdentifyMessage,
  FetchKeysMessage,
  SendMessage,
  AckMessage,
  ReadMessage,
  FetchPendingMessage,
  PongMessage,
]);
export type ClientMessage = z.infer<typeof ClientMessage>;

// --- server -> client frames (always versioned) ---

export function versioned<T extends object>(payload: T): T & { v: 2 } {
  return { ...payload, v: PROTOCOL_VERSION };
}

export type KeysResponse = {
  v: 2;
  type: "keys";
  keys: Record<string, string>;
};

export type PendingDone = {
  v: 2;
  type: "pending_done";
  hasMore: boolean;
};

export type ErrorMessage = {
  v: 2;
  type: "error";
  code: ErrorCode;
  message: string;
};

export function errorMessage(code: ErrorCode, message: string): ErrorMessage {
  return { v: PROTOCOL_VERSION, type: "error", code, message };
}

/** Parse one newline-delimited frame. Returns the message or an ErrorMessage. */
export function parseFrame(raw: string): ClientMessage | ErrorMessage {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return errorMessage("INVALID", "malformed JSON frame");
  }
  if (typeof json !== "object" || json === null || (json as { v?: unknown }).v !== 2) {
    return errorMessage("UPGRADE_REQUIRED", "protocol v2 required");
  }
  const parsed = ClientMessage.safeParse(json);
  if (!parsed.success) {
    return errorMessage("INVALID", "frame failed validation");
  }
  return parsed.data;
}

/** Type guard for parse results. */
export function isErrorMessage(msg: ClientMessage | ErrorMessage): msg is ErrorMessage {
  return (msg as ErrorMessage).type === "error";
}
