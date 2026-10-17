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
  "OFFLINE",
  "RATE_LIMITED",
  "TOO_LARGE",
  "UPGRADE_REQUIRED",
]);
export type ErrorCode = z.infer<typeof ErrorCode>;

const v = z.literal(PROTOCOL_VERSION);
const userIdField = z.string().min(1).max(64);
const secretField = z.string().min(1).max(256);
const messageIdField = z.string().min(1).max(128);
const groupIdField = z.string().min(1).max(128);
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

// Account recovery: bearer token minted by this server (see reclaim.ts).
// The token carries only the user id; the server mints a FRESH secret on
// reclaim and returns it via the normal `registered` reply.
const tokenField = z.string().min(1).max(512);

export const ReclaimMessage = z.object({
  v,
  type: z.literal("reclaim"),
  token: tokenField,
  pubKey: pubKeyField,
});
export type ReclaimMessage = z.infer<typeof ReclaimMessage>;

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
  // Optional group context (e.g. member-to-member history shares filed
  // into the group thread). DMs omit it.
  groupId: groupIdField.optional(),
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

const groupNameField = z.string().min(1).max(64);

export const CreateGroupMessage = z.object({
  v,
  type: z.literal("create_group"),
  name: groupNameField,
  memberIds: z.array(userIdField).min(1).max(49),
});
export type CreateGroupMessage = z.infer<typeof CreateGroupMessage>;

export const AddMembersMessage = z.object({
  v,
  type: z.literal("add_members"),
  groupId: groupIdField,
  userIds: z.array(userIdField).min(1).max(49),
});
export type AddMembersMessage = z.infer<typeof AddMembersMessage>;

export const RemoveMemberMessage = z.object({
  v,
  type: z.literal("remove_member"),
  groupId: groupIdField,
  userId: userIdField,
});
export type RemoveMemberMessage = z.infer<typeof RemoveMemberMessage>;

export const LeaveGroupMessage = z.object({
  v,
  type: z.literal("leave_group"),
  groupId: groupIdField,
  // Chosen successor for admin handover (centralized nicknames): the leaver
  // must be admin, the heir a current member other than themselves. Absent =
  // legacy behavior (longest-tenured auto-pass inside dropMembership).
  heir: userIdField.optional(),
});
export type LeaveGroupMessage = z.infer<typeof LeaveGroupMessage>;

export const RenameGroupMessage = z.object({
  v,
  type: z.literal("rename_group"),
  groupId: groupIdField,
  name: groupNameField,
});
export type RenameGroupMessage = z.infer<typeof RenameGroupMessage>;

export const FetchGroupsMessage = z.object({
  v,
  type: z.literal("fetch_groups"),
});
export type FetchGroupsMessage = z.infer<typeof FetchGroupsMessage>;

const GroupEnvelope = z.object({
  to: userIdField,
  ciphertext: ciphertextField,
  nonce: nonceField,
});

export const SendGroupMessage = z.object({
  v,
  type: z.literal("send_group"),
  clientMessageId: z.string().min(1).max(128),
  groupId: groupIdField,
  envelopes: z.array(GroupEnvelope).min(1).max(50),
  timestamp: z.number().int().nonnegative(),
});
export type SendGroupMessage = z.infer<typeof SendGroupMessage>;

export const RequestHistoryMessage = z.object({
  v,
  type: z.literal("request_history"),
  groupId: groupIdField,
  // Absent `to` = automatic mode: the server elects the oldest online member
  // (presence never leaves the server). Present = legacy manual targeting.
  to: userIdField.optional(),
  // Gap window: rows older than `before` (the requester's earliest local row),
  // up to `limit` rows. Absent = legacy manual semantics. (Replaces the dead
  // `since` field, which no client ever sent and nothing ever read.)
  before: z.number().int().nonnegative().optional(),
  limit: z.number().int().min(1).max(50).optional(),
});
export type RequestHistoryMessage = z.infer<typeof RequestHistoryMessage>;

// Sharer → requester round completion, relayed like the request itself.
// `count` full (= limit) means the requester should prompt the next round;
// anything less means the floor is reached. `floor` (when present) is the
// oldest created_at the sharer served this round — the requester's cursor
// for the next window, so walks advance through already-held rows instead
// of re-serving them. Absent = legacy sharer (requester falls back to
// earliest-tightening). Best-effort: dropped when the
// requester is offline (shares still await in their inbox; the client
// reconciles on sync).
export const ShareHistoryDoneMessage = z.object({
  v,
  type: z.literal("share_history_done"),
  to: userIdField,
  groupId: groupIdField,
  count: z.number().int().nonnegative().max(10000),
  floor: z.number().int().nonnegative().nullish(),
});
export type ShareHistoryDoneMessage = z.infer<typeof ShareHistoryDoneMessage>;

export const ClientMessage = z.discriminatedUnion("type", [
  RegisterMessage,
  IdentifyMessage,
  ReclaimMessage,
  FetchKeysMessage,
  SendMessage,
  AckMessage,
  ReadMessage,
  FetchPendingMessage,
  PongMessage,
  CreateGroupMessage,
  AddMembersMessage,
  RemoveMemberMessage,
  LeaveGroupMessage,
  RenameGroupMessage,
  FetchGroupsMessage,
  SendGroupMessage,
  RequestHistoryMessage,
  ShareHistoryDoneMessage,
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

export type GroupInfo = {
  groupId: string;
  name: string;
  members: { userId: string; role: "admin" | "member"; joinedAt: number }[];
};

export type GroupsResponse = {
  v: 2;
  type: "groups";
  groups: GroupInfo[];
};

export type GroupCreatedResponse = {
  v: 2;
  type: "group_created";
  groupId: string;
};

export type GroupUpdatedNotice = {
  v: 2;
  type: "group_updated";
  groupId: string;
};

export type HistoryRequestNotice = {
  v: 2;
  type: "history_request";
  groupId: string;
  requester: string;
  before?: number;
  limit?: number;
};

export type HistoryDoneNotice = {
  v: 2;
  type: "history_done";
  groupId: string;
  count: number;
  from: string;
  floor?: number;
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
