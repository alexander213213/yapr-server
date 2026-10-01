import { z } from "zod";

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

const userIdField = z.string().min(1).max(64);
const secretField = z.string().min(1).max(256);

export const RegisterMessage = z.object({
  type: z.literal("register"),
});
export type RegisterMessage = z.infer<typeof RegisterMessage>;

export const IdentifyMessage = z.object({
  type: z.literal("identify"),
  userId: userIdField,
  secret: secretField,
});
export type IdentifyMessage = z.infer<typeof IdentifyMessage>;

export const SendMessage = z.object({
  type: z.literal("send_message"),
  clientMessageId: z.string().min(1).max(128),
  to: userIdField,
  text: z.string().min(1).max(8192),
});
export type SendMessage = z.infer<typeof SendMessage>;

export const DeliveryAckMessage = z.object({
  type: z.literal("delivery_ack"),
  messageId: z.string().min(1).max(128),
});
export type DeliveryAckMessage = z.infer<typeof DeliveryAckMessage>;

/** Heartbeat reply from clients (server sends unvalidated `{ type: "ping" }`). */
export const PongMessage = z.object({
  type: z.literal("pong"),
});
export type PongMessage = z.infer<typeof PongMessage>;

export const ClientMessage = z.discriminatedUnion("type", [
  RegisterMessage,
  IdentifyMessage,
  SendMessage,
  DeliveryAckMessage,
  PongMessage,
]);
export type ClientMessage = z.infer<typeof ClientMessage>;

export type ErrorMessage = {
  type: "error";
  code: ErrorCode;
  message: string;
};

export function errorMessage(code: ErrorCode, message: string): ErrorMessage {
  return { type: "error", code, message };
}

/** Parse one newline-delimited frame. Returns the message or an ErrorMessage. */
export function parseFrame(raw: string): ClientMessage | ErrorMessage {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return errorMessage("INVALID", "malformed JSON frame");
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
