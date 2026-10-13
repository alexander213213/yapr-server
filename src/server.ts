import net from "node:net";
import tls from "node:tls";
import fs from "node:fs";
import crypto from "node:crypto";
import db from "./db.js";
import {
  AckMessage,
  AddMembersMessage,
  ClientMessage,
  CreateGroupMessage,
  FetchKeysMessage,
  FetchPendingMessage,
  GroupCreatedResponse,
  GroupInfo,
  GroupUpdatedNotice,
  GroupsResponse,
  HistoryRequestNotice,
  KeysResponse,
  LeaveGroupMessage,
  PendingDone,
  ReadMessage,
  RemoveMemberMessage,
  RenameGroupMessage,
  ReclaimMessage,
  RequestHistoryMessage,
  SendGroupMessage,
  SendMessage,
  errorMessage,
  isErrorMessage,
  parseFrame,
  versioned,
} from "./protocol.js";
import {
  dummyCompare,
  generateGroupId,
  generateMessageId,
  generateSecret,
  generateUserId,
  hashSecret,
  isLegacyPlaintextSecret,
  verifySecret,
} from "./auth.js";
import {
  AUTH_TIMEOUT_MS,
  IDLE_TIMEOUT_MS,
  MAX_FRAME_BYTES,
  MAX_WRITABLE_BYTES,
  PING_INTERVAL_MS,
  RateLimiter,
  registerLimiter,
  sendLimiter,
} from "./limits.js";
import { logger } from "./logger.js";
import { isUniqueViolation } from "./sqlite.js";
import {
  getReclaimKey,
  mintReclaimToken,
  verifyReclaimToken,
} from "./reclaim.js";

export type IncomingEnvelope = {
  v: 2;
  type: "incoming";
  messageId: string;
  from: string;
  ciphertext: string;
  nonce: string;
  timestamp: number;
  groupId?: string;
};

export type ServerAckMessage = {
  v: 2;
  type: "server_ack";
  clientMessageId: string;
  messageId: string;
  messageIds?: string[];
  status: "accepted";
  timestamp: number;
};

export type ReadReceipt = {
  v: 2;
  type: "read_receipt";
  messageId: string;
  reader: string;
};

type AuthedSocket = net.Socket & {
  userId?: string;
  lastActivity?: number;
};

type UserRow = {
  user_id: string;
  secret: string;
  secret_hash: string | null;
  pubkey: string | null;
  created_at: number;
};

type PendingRow = {
  message_id: string;
  client_message_id: string;
  sender_id: string;
  recipient_id: string;
  group_id: string | null;
  ciphertext: string;
  nonce: string;
  sender_timestamp: number;
  created_at: number;
};

type ProcessedMessageRow = {
  message_id: string;
  client_message_id: string;
  sender_id: string;
  created_at: number;
};

type GroupRow = {
  group_id: string;
  name: string;
  creator_id: string;
  created_at: number;
};

type MemberRow = {
  group_id: string;
  user_id: string;
  role: "admin" | "member";
  joined_at: number;
};

const MAX_GROUP_MEMBERS = 50;
/** send_group carries up to 50 envelopes; sized accordingly (DoS-bounded). */
const MAX_GROUP_FRAME_BYTES = Number(process.env.MAX_GROUP_FRAME_BYTES ?? 512 * 1024);

const PORT = Number(process.env.PORT ?? "9000");
if (!Number.isInteger(PORT) || PORT <= 0 || PORT > 65535) {
  throw new Error(`Invalid PORT: ${process.env.PORT ?? "(unset)"}`);
}

function loadTlsCredentials(): { cert: string; key: string } {
  const cert =
    process.env.TLS_CERT ??
    (process.env.TLS_CERT_FILE ? fs.readFileSync(process.env.TLS_CERT_FILE, "utf8") : undefined);
  const key =
    process.env.TLS_KEY ??
    (process.env.TLS_KEY_FILE ? fs.readFileSync(process.env.TLS_KEY_FILE, "utf8") : undefined);
  if (!cert || !key) {
    throw new Error(
      "TLS cert/key missing: set TLS_CERT_FILE/TLS_KEY_FILE (generate dev certs with `npm run certs`) or inline TLS_CERT/TLS_KEY PEM. The server is fail-closed: no plaintext fallback."
    );
  }
  return { cert, key };
}

const connections = new Map<string, AuthedSocket>();
const authLimiter = new RateLimiter(
  Number(process.env.RATE_AUTH_MAX ?? 20),
  Number(process.env.RATE_AUTH_WINDOW_MS ?? 60_000)
);
const keysLimiter = new RateLimiter(
  Number(process.env.RATE_KEYS_MAX ?? 60),
  Number(process.env.RATE_KEYS_WINDOW_MS ?? 60_000)
);
const groupLimiter = new RateLimiter(
  Number(process.env.RATE_GROUP_MAX ?? 30),
  Number(process.env.RATE_GROUP_WINDOW_MS ?? 60_000)
);

/** Operational counters, summarized to the log every STATS_INTERVAL_MS. */
const stats = {
  startedAt: Date.now(),
  liveConnections: 0,
  registered: 0,
  identified: 0,
  relayed: 0,
  acked: 0,
  readsForwarded: 0,
  keysServed: 0,
  framesRejected: 0,
  groupsCreated: 0,
  groupSends: 0,
};
const STATS_INTERVAL_MS = Number(process.env.STATS_INTERVAL_MS ?? 60_000);

function pendingDepth(): number {
  try {
    const row = db.prepare(`SELECT COUNT(*) AS n FROM pending_messages`).get() as {
      n: number;
    };
    return row.n;
  } catch {
    return -1;
  }
}

/** Dedup horizon for idempotent resends; also the processed-table GC TTL. */
export const PROCESSED_TTL_MS = Number(
  process.env.PROCESSED_TTL_MS ?? 30 * 24 * 3600 * 1000
);
const GC_INTERVAL_MS = Number(process.env.GC_INTERVAL_MS ?? 3600 * 1000);

const insertUserStmt = db.prepare(`
    INSERT INTO users (user_id, secret, secret_hash, pubkey)
    VALUES (?, ?, ?, ?)
`);

const findUserStmt = db.prepare(`
    SELECT user_id, secret, secret_hash, pubkey, created_at
    FROM users
    WHERE user_id = ?
`);

const updateSecretHashStmt = db.prepare(`
    UPDATE users SET secret = '', secret_hash = ?
    WHERE user_id = ?
`);

const insertMessageStmt = db.prepare(`
    INSERT INTO pending_messages
      (message_id, client_message_id, sender_id, recipient_id, group_id,
       ciphertext, nonce, sender_timestamp, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const findFirstPageStmt = db.prepare(`
    SELECT message_id, client_message_id, sender_id, recipient_id, group_id,
           ciphertext, nonce, sender_timestamp, created_at
    FROM pending_messages
    WHERE recipient_id = ?
    ORDER BY created_at ASC, message_id ASC
    LIMIT ?
`);

const findNextPageStmt = db.prepare(`
    SELECT message_id, client_message_id, sender_id, recipient_id, group_id,
           ciphertext, nonce, sender_timestamp, created_at
    FROM pending_messages
    WHERE recipient_id = ?
      AND (created_at > ? OR (created_at = ? AND message_id > ?))
    ORDER BY created_at ASC, message_id ASC
    LIMIT ?
`);

const findMessageByMessageIdStmt = db.prepare(`
    SELECT * FROM pending_messages
    WHERE message_id = ?
`);

const deleteMessageByMessageIdStmt = db.prepare(`
    DELETE FROM pending_messages
    WHERE message_id = ?
`);

const findPendingByClientMessageIdStmt = db.prepare(`
    SELECT message_id, client_message_id FROM pending_messages
    WHERE sender_id = ? AND client_message_id = ?
    ORDER BY rowid ASC
`);

const insertProcessedMessageStmt = db.prepare(`
    INSERT INTO processed_messages (message_id, client_message_id, sender_id)
    VALUES (?, ?, ?)
`);

const deleteProcessedByClientMessageIdStmt = db.prepare(`
    DELETE FROM processed_messages
    WHERE sender_id = ? AND client_message_id = ?
`);

const findProcessedMessageByClientMessageIdStmt = db.prepare(`
    SELECT * FROM processed_messages
    WHERE client_message_id = ? AND sender_id = ?
    ORDER BY rowid ASC
`);

const findProcessedMessageByMessageIdStmt = db.prepare(`
    SELECT sender_id, client_message_id, message_id FROM processed_messages
    WHERE message_id = ?
`);

const deleteProcessedOlderThanStmt = db.prepare(`
    DELETE FROM processed_messages
    WHERE created_at < ?
`);

const insertGroupStmt = db.prepare(`
    INSERT INTO groups (group_id, name, creator_id, created_at)
    VALUES (?, ?, ?, ?)
`);

const insertMemberStmt = db.prepare(`
    INSERT OR IGNORE INTO group_members (group_id, user_id, role, joined_at)
    VALUES (?, ?, ?, ?)
`);

const findGroupStmt = db.prepare(`
    SELECT group_id, name, creator_id, created_at FROM groups WHERE group_id = ?
`);

const findMemberStmt = db.prepare(`
    SELECT group_id, user_id, role, joined_at FROM group_members
    WHERE group_id = ? AND user_id = ?
`);

const listGroupMembersStmt = db.prepare(`
    SELECT group_id, user_id, role, joined_at FROM group_members
    WHERE group_id = ?
    ORDER BY joined_at ASC, user_id ASC
`);

const countGroupMembersStmt = db.prepare(`
    SELECT COUNT(*) AS n FROM group_members WHERE group_id = ?
`);

const removeMemberStmt = db.prepare(`
    DELETE FROM group_members WHERE group_id = ? AND user_id = ?
`);

const deleteGroupMembersStmt = db.prepare(`
    DELETE FROM group_members WHERE group_id = ?
`);

const deleteGroupStmt = db.prepare(`
    DELETE FROM groups WHERE group_id = ?
`);

const updateGroupNameStmt = db.prepare(`
    UPDATE groups SET name = ? WHERE group_id = ?
`);

const updateMemberRoleStmt = db.prepare(`
    UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ?
`);

const longestTenuredMemberStmt = db.prepare(`
    SELECT user_id FROM group_members
    WHERE group_id = ? AND user_id != ?
    ORDER BY joined_at ASC, user_id ASC
    LIMIT 1
`);

const listUserGroupsStmt = db.prepare(`
    SELECT g.group_id, g.name, g.creator_id, g.created_at
    FROM groups g JOIN group_members m ON m.group_id = g.group_id
    WHERE m.user_id = ?
    ORDER BY g.created_at ASC, g.group_id ASC
`);

const deletePendingForStmt = db.prepare(`
    DELETE FROM pending_messages WHERE recipient_id = ? AND group_id = ?
`);

function findPubKeys(userIds: string[]): Record<string, string> {
  if (userIds.length === 0) return {};
  const placeholders = userIds.map(() => "?").join(",");
  const rows = db
    .prepare(`SELECT user_id, pubkey FROM users WHERE user_id IN (${placeholders})`)
    .all(...userIds) as { user_id: string; pubkey: string | null }[];
  const keys: Record<string, string> = {};
  for (const row of rows) {
    if (row.pubkey) keys[row.user_id] = row.pubkey;
  }
  return keys;
}

// node:sqlite has no db.transaction() helper (unlike better-sqlite3),
// so the ack delete+insert is wrapped in explicit BEGIN/COMMIT.
function ackTx(messageId: string, userId: string) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const pendingMsg = findMessageByMessageIdStmt.get(messageId) as PendingRow | undefined;

    if (!pendingMsg) throw new Error("Unknown Ack");
    if (pendingMsg.recipient_id !== userId) throw new Error("Wrong messageId or userId");

    deleteMessageByMessageIdStmt.run(pendingMsg.message_id);
    insertProcessedMessageStmt.run(
      pendingMsg.message_id,
      pendingMsg.client_message_id,
      pendingMsg.sender_id
    );
    db.exec("COMMIT");
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // Best effort: the transaction may already be rolled back.
    }
    throw err;
  }
}

function send(socket: net.Socket, payload: unknown): boolean {
  if (socket.destroyed || !socket.writable) return false;
  if (socket.writableLength > MAX_WRITABLE_BYTES) {
    logger.warn("slow consumer, disconnecting");
    socket.destroy();
    return false;
  }
  socket.write(JSON.stringify(payload) + "\n");
  return true;
}

function clientIp(socket: net.Socket): string {
  return socket.remoteAddress ?? "unknown";
}

function registerUser(socket: AuthedSocket, pubKey: string) {
  let userId: string;
  try {
    userId = generateUserId((id) => findUserStmt.get(id) !== undefined);
  } catch {
    send(socket, errorMessage("INVALID", "registration failed, retry"));
    return;
  }
  const secret = generateSecret();
  insertUserStmt.run(userId, "", hashSecret(secret), pubKey);
  stats.registered += 1;

  send(socket, versioned({
    type: "registered",
    userId,
    secret,
    ...reclaimTokenField(userId),
  }));
}

/**
 * Mint a recovery token for an account, or nothing when the reclaim key is
 * unconfigured (feature off). Returned object spreads into replies; old
 * clients strip-ignored the unknown field.
 */
function reclaimTokenField(userId: string): { reclaimToken?: string } {
  const key = getReclaimKey();
  if (!key) return {};
  return { reclaimToken: mintReclaimToken(key, userId) };
}

/**
 * Silent account recovery after server data loss. The bearer token re-creates
 * the account row with a FRESH secret (returned via the normal `registered`
 * reply); the claimer must then identify normally. Reclaim on an existing id
 * is rejected: a stolen token must never reset a live account. Group
 * memberships are never restored (a stale token must not re-admit a removed
 * member) — re-adding stays an admin action.
 */
function handleReclaim(socket: AuthedSocket, message: ReclaimMessage) {
  const key = getReclaimKey();
  if (!key) {
    send(socket, errorMessage("INVALID", "recovery unavailable"));
    return;
  }
  const userId = verifyReclaimToken(key, message.token);
  if (!userId) {
    send(socket, errorMessage("INVALID", "recovery failed"));
    return;
  }
  if (findUserStmt.get(userId)) {
    send(socket, errorMessage("INVALID", "already registered"));
    return;
  }
  const secret = generateSecret();
  try {
    insertUserStmt.run(userId, "", hashSecret(secret), message.pubKey);
  } catch (err: unknown) {
    if (isUniqueViolation(err)) {
      send(socket, errorMessage("INVALID", "already registered"));
      return;
    }
    throw err;
  }
  stats.registered += 1;
  logger.info({ userId }, "account recovered via reclaim token");
  send(socket, versioned({
    type: "registered",
    userId,
    secret,
    ...reclaimTokenField(userId),
  }));
}

function verifyLogin(secret: string, user: UserRow): boolean {
  if (user.secret_hash && !isLegacyPlaintextSecret(user.secret_hash)) {
    return verifySecret(secret, user.secret_hash);
  }
  // Legacy v1 row: compare against the stored plaintext, then transparently
  // upgrade to a hash so the plaintext leaves the database.
  if (user.secret.length !== secret.length) {
    dummyCompare(secret);
    return false;
  }
  const ok = crypto.timingSafeEqual(Buffer.from(user.secret), Buffer.from(secret));
  if (ok) {
    try {
      updateSecretHashStmt.run(hashSecret(secret), user.user_id);
    } catch (err) {
      logger.warn({ err }, "failed to upgrade legacy secret hash");
    }
  }
  return ok;
}

function identifyUser(socket: AuthedSocket, userId: string, secret: string) {
  const user = findUserStmt.get(userId) as UserRow | undefined;

  // Same code path and reply for unknown users and wrong secrets.
  if (!user || !verifyLogin(secret, user)) {
    if (!user) dummyCompare(secret);
    send(socket, errorMessage("UNAUTH", "authentication failed"));
    return;
  }
  const authedSocket = socket as AuthedSocket;
  authedSocket.userId = userId;
  authedSocket.lastActivity = Date.now();
  const userSocket = connections.get(userId);
  if (!!userSocket) {
    connections.delete(userId);
    send(userSocket, errorMessage("UNAUTH", "signed in from another device"));
    userSocket.end();
  }
  connections.set(userId, authedSocket);
  stats.identified += 1;
  sendPendingPage(socket);
  send(socket, versioned({
    type: "identified",
    userId,
    ...reclaimTokenField(userId),
  }));
  socket.once("close", () => {
    const current = connections.get(userId);
    if (current === socket) {
      connections.delete(userId);
    }
  });
}

const DEFAULT_PAGE_LIMIT = 50;
const MAX_PAGE_LIMIT = 200;

function toIncomingEnvelope(row: PendingRow): IncomingEnvelope {
  const envelope: IncomingEnvelope = versioned({
    type: "incoming",
    from: row.sender_id,
    messageId: row.message_id,
    ciphertext: row.ciphertext,
    nonce: row.nonce,
    timestamp: row.created_at,
  });
  if (row.group_id) envelope.groupId = row.group_id;
  return envelope;
}

function groupInfoFor(groupId: string): GroupInfo | undefined {
  const group = findGroupStmt.get(groupId) as GroupRow | undefined;
  if (!group) return undefined;
  const members = listGroupMembersStmt.all(groupId) as MemberRow[];
  return {
    groupId: group.group_id,
    name: group.name,
    members: members.map((m) => ({ userId: m.user_id, role: m.role, joinedAt: m.joined_at })),
  };
}

/** Notify every online member that a group's roster or name changed. */
function broadcastGroupUpdated(groupId: string): void {
  const members = listGroupMembersStmt.all(groupId) as MemberRow[];
  const notice: GroupUpdatedNotice = versioned({ type: "group_updated", groupId });
  for (const member of members) {
    const sock = connections.get(member.user_id);
    if (sock) send(sock, notice);
  }
}

/** Deliver one page of the offline inbox, oldest first, then a done marker. */
function sendPendingPage(
  socket: AuthedSocket,
  cursor?: { createdAt: number; messageId: string },
  limit?: number
) {
  if (!socket.userId) return;
  const take = Math.min(limit ?? DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
  const rows = (
    cursor
      ? findNextPageStmt.all(
          socket.userId,
          cursor.createdAt,
          cursor.createdAt,
          cursor.messageId,
          take + 1
        )
      : findFirstPageStmt.all(socket.userId, take + 1)
  ) as PendingRow[];
  const hasMore = rows.length > take;
  for (const row of rows.slice(0, take)) {
    if (!send(socket, toIncomingEnvelope(row))) return;
  }
  const done: PendingDone = versioned({ type: "pending_done", hasMore });
  send(socket, done);
}

function handleFetchKeys(socket: AuthedSocket, message: FetchKeysMessage) {
  if (!socket.userId) return;
  const keys = findPubKeys(message.userIds);
  stats.keysServed += 1;
  const response: KeysResponse = versioned({ type: "keys", keys });
  send(socket, response);
}

function handleFetchPending(socket: AuthedSocket, message: FetchPendingMessage) {
  if (!socket.userId) return;
  sendPendingPage(socket, message.cursor, message.limit);
}

function requireGroupAdmin(
  socket: AuthedSocket,
  groupId: string
): { group: GroupRow; member: MemberRow } | undefined {
  const userId = socket.userId;
  if (!userId) {
    send(socket, errorMessage("UNAUTH", "identify first"));
    return undefined;
  }
  const group = findGroupStmt.get(groupId) as GroupRow | undefined;
  if (!group) {
    send(socket, errorMessage("NOT_FOUND", "group not found"));
    return undefined;
  }
  const member = findMemberStmt.get(groupId, userId) as MemberRow | undefined;
  if (!member || member.role !== "admin") {
    send(socket, errorMessage("UNAUTH", "group admin required"));
    return undefined;
  }
  return { group, member };
}

function handleCreateGroup(socket: AuthedSocket, message: CreateGroupMessage) {
  if (!socket.userId) return;
  const creatorId: string = socket.userId;
  const memberIds = [...new Set(message.memberIds)].filter((id) => id !== creatorId);
  if (memberIds.length + 1 > MAX_GROUP_MEMBERS) {
    send(socket, errorMessage("INVALID", `groups are capped at ${MAX_GROUP_MEMBERS} members`));
    return;
  }
  for (const id of memberIds) {
    if (!findUserStmt.get(id)) {
      send(socket, errorMessage("NOT_FOUND", "member not found"));
      return;
    }
  }
  const now = Date.now();
  const groupId = generateGroupId();
  db.exec("BEGIN IMMEDIATE");
  try {
    insertGroupStmt.run(groupId, message.name, creatorId, now);
    insertMemberStmt.run(groupId, creatorId, "admin", now);
    for (const id of memberIds) {
      insertMemberStmt.run(groupId, id, "member", now);
    }
    db.exec("COMMIT");
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // Best effort.
    }
    throw err;
  }
  stats.groupsCreated += 1;
  const created: GroupCreatedResponse = versioned({ type: "group_created", groupId });
  send(socket, created);
  broadcastGroupUpdated(groupId);
}

function handleAddMembers(socket: AuthedSocket, message: AddMembersMessage) {
  const gate = requireGroupAdmin(socket, message.groupId);
  if (!gate) return;
  const memberIds = [...new Set(message.userIds)];
  for (const id of memberIds) {
    if (!findUserStmt.get(id)) {
      send(socket, errorMessage("NOT_FOUND", "member not found"));
      return;
    }
  }
  const current = (countGroupMembersStmt.get(message.groupId) as { n: number }).n;
  const fresh = memberIds.filter(
    (id) => !findMemberStmt.get(message.groupId, id)
  );
  if (current + fresh.length > MAX_GROUP_MEMBERS) {
    send(socket, errorMessage("INVALID", `groups are capped at ${MAX_GROUP_MEMBERS} members`));
    return;
  }
  const now = Date.now();
  for (const id of fresh) {
    insertMemberStmt.run(message.groupId, id, "member", now);
  }
  broadcastGroupUpdated(message.groupId);
}

function dropMembership(groupId: string, userId: string): void {
  const departing = findMemberStmt.get(groupId, userId) as MemberRow | undefined;
  removeMemberStmt.run(groupId, userId);
  // Undeliverable inbox rows for the departed member must not leak.
  deletePendingForStmt.run(userId, groupId);
  const remaining = (countGroupMembersStmt.get(groupId) as { n: number }).n;
  if (remaining === 0) {
    deleteGroupMembersStmt.run(groupId);
    deleteGroupStmt.run(groupId);
    return;
  }
  // An admin departing without successors promotes the longest-tenured member.
  if (departing?.role === "admin") {
    const admins = (listGroupMembersStmt.all(groupId) as MemberRow[]).filter(
      (m) => m.role === "admin"
    );
    if (admins.length === 0) {
      const heir = longestTenuredMemberStmt.get(groupId, userId) as
        | { user_id: string }
        | undefined;
      if (heir) {
        updateMemberRoleStmt.run("admin", groupId, heir.user_id);
      }
    }
  }
}

function handleRemoveMember(socket: AuthedSocket, message: RemoveMemberMessage) {
  const gate = requireGroupAdmin(socket, message.groupId);
  if (!gate) return;
  if (message.userId === socket.userId) {
    send(socket, errorMessage("INVALID", "use leave_group to remove yourself"));
    return;
  }
  dropMembership(message.groupId, message.userId);
  broadcastGroupUpdated(message.groupId);
  const removedSocket = connections.get(message.userId);
  if (removedSocket) {
    send(removedSocket, versioned({ type: "group_updated", groupId: message.groupId }));
  }
}

function handleLeaveGroup(socket: AuthedSocket, message: LeaveGroupMessage) {
  if (!socket.userId) return;
  const member = findMemberStmt.get(message.groupId, socket.userId) as MemberRow | undefined;
  if (!member) {
    send(socket, errorMessage("NOT_FOUND", "not a group member"));
    return;
  }
  const userId: string = socket.userId;
  dropMembership(message.groupId, userId);
  broadcastGroupUpdated(message.groupId);
}

function handleRenameGroup(socket: AuthedSocket, message: RenameGroupMessage) {
  const gate = requireGroupAdmin(socket, message.groupId);
  if (!gate) return;
  updateGroupNameStmt.run(message.name, message.groupId);
  broadcastGroupUpdated(message.groupId);
}

function handleFetchGroups(socket: AuthedSocket) {
  if (!socket.userId) return;
  const groups = (listUserGroupsStmt.all(socket.userId) as GroupRow[]).map((g) => {
    const info = groupInfoFor(g.group_id);
    return (
      info ?? {
        groupId: g.group_id,
        name: g.name,
        members: [] as GroupInfo["members"],
      }
    );
  });
  const response: GroupsResponse = versioned({ type: "groups", groups });
  send(socket, response);
}

function handleRequestHistory(socket: AuthedSocket, message: RequestHistoryMessage) {
  if (!socket.userId) return;
  const requester: string = socket.userId;
  const requesterMember = findMemberStmt.get(message.groupId, requester) as MemberRow | undefined;
  const targetMember = findMemberStmt.get(message.groupId, message.to) as
    | MemberRow
    | undefined;
  if (!requesterMember || !targetMember) {
    send(socket, errorMessage("NOT_FOUND", "not a group member"));
    return;
  }
  const targetSocket = connections.get(message.to);
  if (!targetSocket) {
    send(socket, errorMessage("OFFLINE", "member offline"));
    return;
  }
  const notice: HistoryRequestNotice = versioned({
    type: "history_request",
    groupId: message.groupId,
    requester,
  });
  send(targetSocket, notice);
}

type EnvelopeRef = { message_id: string; client_message_id: string };

/** Idempotent send lookup, scoped to the sender. One clientMessageId may own
 *  several rows (group fan-out), so this returns all of them. Stale dedup rows
 *  are reaped so ids can be reused after the TTL expires. */
function findExistingEnvelopes(
  senderId: string,
  clientMessageId: string
): EnvelopeRef[] {
  const pending = findPendingByClientMessageIdStmt.all(senderId, clientMessageId) as
    | EnvelopeRef[]
    | undefined;
  if (pending && pending.length > 0) return pending;
  const processed = (
    findProcessedMessageByClientMessageIdStmt.all(senderId, clientMessageId) as
      | (ProcessedMessageRow & { created_at: number })[]
      | undefined
  ) ?? [];
  const fresh = processed.filter((p) => Date.now() - p.created_at < PROCESSED_TTL_MS);
  if (fresh.length > 0) {
    return fresh.map((p) => ({
      message_id: p.message_id,
      client_message_id: p.client_message_id,
    }));
  }
  if (processed.length > 0) {
    deleteProcessedByClientMessageIdStmt.run(senderId, clientMessageId);
  }
  return [];
}

function relayMessage(socket: AuthedSocket, message: SendMessage) {
  if (!socket.userId) return;
  const senderId: string = socket.userId;
  const recipient = findUserStmt.get(message.to) as UserRow | undefined;
  if (!recipient) {
    send(socket, errorMessage("NOT_FOUND", "recipient not found"));
    return;
  }
  const now = Date.now();
  const existing = findExistingEnvelopes(senderId, message.clientMessageId);
  if (existing.length > 0) {
    const first = existing[0];
    if (!first) {
      send(socket, errorMessage("INVALID", "could not process frame"));
      return;
    }
    const ack: ServerAckMessage = versioned({
      type: "server_ack",
      clientMessageId: first.client_message_id,
      messageId: first.message_id,
      status: "accepted",
      timestamp: now,
    });
    stats.relayed += 1;
    send(socket, ack);
    return;
  }
  // Group-tagged direct sends (e.g. member-to-member history shares) require
  // both ends to be current members; otherwise the tag could file mail into a
  // stranger's group thread.
  const groupId = message.groupId ?? null;
  if (groupId) {
    const senderMember = findMemberStmt.get(groupId, senderId) as MemberRow | undefined;
    const recipientMember = findMemberStmt.get(groupId, message.to) as MemberRow | undefined;
    if (!senderMember || !recipientMember) {
      send(socket, errorMessage("INVALID", "group tag requires both ends as members"));
      return;
    }
  }
  const messageId = generateMessageId();
  try {
    insertMessageStmt.run(
      messageId,
      message.clientMessageId,
      senderId,
      message.to,
      groupId,
      message.ciphertext,
      message.nonce,
      message.timestamp,
      now
    );
  } catch (err: unknown) {
    if (isUniqueViolation(err)) {
      // Lost race with a concurrent identical send: answer from the stored row.
      const raced = findExistingEnvelopes(senderId, message.clientMessageId);
      const hit = raced[0];
      if (hit) {
        const ack: ServerAckMessage = versioned({
          type: "server_ack",
          clientMessageId: hit.client_message_id,
          messageId: hit.message_id,
          status: "accepted",
          timestamp: now,
        });
        send(socket, ack);
      }
      return;
    }
    throw err;
  }
  const ack: ServerAckMessage = versioned({
    type: "server_ack",
    clientMessageId: message.clientMessageId,
    messageId,
    status: "accepted",
    timestamp: now,
  });
  stats.relayed += 1;
  send(socket, ack);

  const recipientSocket = connections.get(message.to);

  if (!recipientSocket) return;
  // Same `now` as the ack: sender and recipient agree on the timestamp.
  const payload: IncomingEnvelope = versioned({
    type: "incoming",
    from: senderId,
    messageId,
    ciphertext: message.ciphertext,
    nonce: message.nonce,
    timestamp: now,
  });
  if (groupId) payload.groupId = groupId;

  send(recipientSocket, payload);
}

function relayGroupMessage(socket: AuthedSocket, message: SendGroupMessage) {
  if (!socket.userId) return;
  const senderId: string = socket.userId;
  const group = findGroupStmt.get(message.groupId) as GroupRow | undefined;
  if (!group) {
    send(socket, errorMessage("NOT_FOUND", "group not found"));
    return;
  }
  const senderMember = findMemberStmt.get(message.groupId, senderId) as MemberRow | undefined;
  if (!senderMember) {
    send(socket, errorMessage("UNAUTH", "not a group member"));
    return;
  }
  const members = listGroupMembersStmt.all(message.groupId) as MemberRow[];
  const memberIds = new Set(members.map((m) => m.user_id));
  // Dedupe defensively; every envelope must target a current member, never self.
  const targets = [...new Set(message.envelopes.map((e) => e.to))];
  for (const to of targets) {
    if (to === senderId || !memberIds.has(to)) {
      send(socket, errorMessage("INVALID", "envelope recipient is not a group member"));
      return;
    }
  }
  if (targets.length === 0) {
    send(socket, errorMessage("INVALID", "no recipients"));
    return;
  }
  const now = Date.now();
  const existing = findExistingEnvelopes(senderId, message.clientMessageId);
  if (existing.length > 0) {
    const ack: ServerAckMessage = versioned({
      type: "server_ack",
      clientMessageId: message.clientMessageId,
      messageId: existing[0]?.message_id ?? "",
      messageIds: existing.map((e) => e.message_id),
      status: "accepted",
      timestamp: now,
    });
    stats.relayed += 1;
    stats.groupSends += 1;
    send(socket, ack);
    return;
  }
  const byRecipient = new Map(message.envelopes.map((e) => [e.to, e]));
  const storedIds: string[] = [];
  const idByRecipient = new Map<string, string>();
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const to of targets) {
      const env = byRecipient.get(to);
      if (!env) continue;
      const messageId = generateMessageId();
      insertMessageStmt.run(
        messageId,
        message.clientMessageId,
        senderId,
        to,
        message.groupId,
        env.ciphertext,
        env.nonce,
        message.timestamp,
        now
      );
      storedIds.push(messageId);
      idByRecipient.set(to, messageId);
    }
    db.exec("COMMIT");
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // Best effort.
    }
    if (isUniqueViolation(err)) {
      const raced = findExistingEnvelopes(senderId, message.clientMessageId);
      if (raced.length > 0) {
        const ack: ServerAckMessage = versioned({
          type: "server_ack",
          clientMessageId: message.clientMessageId,
          messageId: raced[0]?.message_id ?? "",
          messageIds: raced.map((e) => e.message_id),
          status: "accepted",
          timestamp: now,
        });
        send(socket, ack);
      }
      return;
    }
    throw err;
  }
  const ack: ServerAckMessage = versioned({
    type: "server_ack",
    clientMessageId: message.clientMessageId,
    messageId: storedIds[0] ?? "",
    messageIds: storedIds,
    status: "accepted",
    timestamp: now,
  });
  stats.relayed += 1;
  stats.groupSends += 1;
  send(socket, ack);

  const envByRecipient = new Map(message.envelopes.map((e) => [e.to, e]));
  for (const to of targets) {
    const recipientSocket = connections.get(to);
    const messageId = idByRecipient.get(to);
    if (!recipientSocket || !messageId) continue;
    const env = envByRecipient.get(to);
    if (!env) continue;
    const payload: IncomingEnvelope = versioned({
      type: "incoming",
      from: senderId,
      messageId,
      ciphertext: env.ciphertext,
      nonce: env.nonce,
      timestamp: now,
    });
    payload.groupId = message.groupId;
    send(recipientSocket, payload);
  }
}

function handleAck(socket: AuthedSocket, message: AckMessage) {
  if (!socket.userId) return;
  try {
    ackTx(message.messageId, socket.userId);
    stats.acked += 1;
  } catch {
    // Already acked (idempotent OK) vs unknown id: only the latter is an error.
    const processed = findProcessedMessageByMessageIdStmt.get(message.messageId) as
      | { message_id: string }
      | undefined;
    if (!processed) {
      send(socket, errorMessage("INVALID", "ack failed"));
    }
  }
}

/** Best-effort sender notification. Dropped when the sender is offline;
 *  never persisted. message_ids are unguessable UUIDs, so no recipient
 *  check is enforced on already-acked rows. */
function handleRead(socket: AuthedSocket, message: ReadMessage) {
  if (!socket.userId) return;
  const reader: string = socket.userId;
  const pending = findMessageByMessageIdStmt.get(message.messageId) as PendingRow | undefined;
  let senderId: string | undefined;
  if (pending && pending.recipient_id === reader) {
    senderId = pending.sender_id;
  } else {
    const processed = findProcessedMessageByMessageIdStmt.get(message.messageId) as
      | { sender_id: string }
      | undefined;
    if (processed) senderId = processed.sender_id;
  }
  if (!senderId) {
    send(socket, errorMessage("INVALID", "unknown message"));
    return;
  }
  const senderSocket = connections.get(senderId);
  if (!senderSocket) return;
  const receipt: ReadReceipt = versioned({ type: "read_receipt", messageId: message.messageId, reader });
  stats.readsForwarded += 1;
  send(senderSocket, receipt);
}

function requireAuth(socket: AuthedSocket): socket is AuthedSocket & { userId: string } {
  if (!socket.userId) {
    send(socket, errorMessage("UNAUTH", "identify first"));
    return false;
  }
  return true;
}

function handleMessage(socket: AuthedSocket, message: ClientMessage) {
  const ip = clientIp(socket);
  switch (message.type) {
    case "register":
      if (!registerLimiter.take(ip)) {
        send(socket, errorMessage("RATE_LIMITED", "too many registrations"));
        return;
      }
      registerUser(socket, message.pubKey);
      break;

    case "identify":
      if (!authLimiter.take(ip)) {
        send(socket, errorMessage("RATE_LIMITED", "too many login attempts"));
        return;
      }
      identifyUser(socket, message.userId, message.secret);
      break;

    case "reclaim":
      if (!registerLimiter.take(ip)) {
        send(socket, errorMessage("RATE_LIMITED", "too many registrations"));
        return;
      }
      handleReclaim(socket, message);
      break;

    case "fetch_keys":
      if (!requireAuth(socket)) return;
      if (!keysLimiter.take(socket.userId)) {
        send(socket, errorMessage("RATE_LIMITED", "too many key lookups"));
        return;
      }
      handleFetchKeys(socket, message);
      break;

    case "send":
      if (!requireAuth(socket)) return;
      if (!sendLimiter.take(socket.userId)) {
        send(socket, errorMessage("RATE_LIMITED", "sending too fast"));
        return;
      }
      relayMessage(socket, message);
      break;
    case "send_group":
      if (!requireAuth(socket)) return;
      if (!sendLimiter.take(socket.userId)) {
        send(socket, errorMessage("RATE_LIMITED", "sending too fast"));
        return;
      }
      relayGroupMessage(socket, message);
      break;
    case "ack":
      if (!requireAuth(socket)) return;
      handleAck(socket, message);
      break;
    case "read":
      if (!requireAuth(socket)) return;
      handleRead(socket, message);
      break;
    case "fetch_pending":
      if (!requireAuth(socket)) return;
      handleFetchPending(socket, message);
      break;
    case "create_group":
      if (!requireAuth(socket)) return;
      if (!groupLimiter.take(socket.userId)) {
        send(socket, errorMessage("RATE_LIMITED", "too many group operations"));
        return;
      }
      handleCreateGroup(socket, message);
      break;
    case "add_members":
      if (!requireAuth(socket)) return;
      if (!groupLimiter.take(socket.userId)) {
        send(socket, errorMessage("RATE_LIMITED", "too many group operations"));
        return;
      }
      handleAddMembers(socket, message);
      break;
    case "remove_member":
      if (!requireAuth(socket)) return;
      if (!groupLimiter.take(socket.userId)) {
        send(socket, errorMessage("RATE_LIMITED", "too many group operations"));
        return;
      }
      handleRemoveMember(socket, message);
      break;
    case "leave_group":
      if (!requireAuth(socket)) return;
      if (!groupLimiter.take(socket.userId)) {
        send(socket, errorMessage("RATE_LIMITED", "too many group operations"));
        return;
      }
      handleLeaveGroup(socket, message);
      break;
    case "rename_group":
      if (!requireAuth(socket)) return;
      if (!groupLimiter.take(socket.userId)) {
        send(socket, errorMessage("RATE_LIMITED", "too many group operations"));
        return;
      }
      handleRenameGroup(socket, message);
      break;
    case "fetch_groups":
      if (!requireAuth(socket)) return;
      if (!groupLimiter.take(socket.userId)) {
        send(socket, errorMessage("RATE_LIMITED", "too many group operations"));
        return;
      }
      handleFetchGroups(socket);
      break;
    case "request_history":
      if (!requireAuth(socket)) return;
      if (!groupLimiter.take(socket.userId)) {
        send(socket, errorMessage("RATE_LIMITED", "too many group operations"));
        return;
      }
      handleRequestHistory(socket, message);
      break;
    case "pong":
      break;
  }
}

function onConnection(rawSocket: net.Socket) {
  rawSocket.setEncoding("utf8");
  const socket = rawSocket as AuthedSocket;
  socket.lastActivity = Date.now();
  stats.liveConnections += 1;
  let buffer = "";

  const authTimer = setTimeout(() => {
    if (!socket.userId) {
      send(socket, errorMessage("UNAUTH", "identify within 10s of connecting"));
      socket.destroy();
    }
  }, AUTH_TIMEOUT_MS);
  authTimer.unref();

  socket.once("close", () => {
    stats.liveConnections = Math.max(0, stats.liveConnections - 1);
    clearTimeout(authTimer);
  });
  socket.on("error", (err) => {
    logger.warn({ err: String(err), ip: clientIp(socket) }, "socket error");
  });

  socket.on("data", (chunk: string) => {
    socket.lastActivity = Date.now();
    buffer += chunk;

    if (buffer.length > MAX_GROUP_FRAME_BYTES + 4096) {
      send(socket, errorMessage("TOO_LARGE", "frame too large"));
      socket.destroy();
      return;
    }

    let newlineIndex = buffer.indexOf("\n");

    while (newlineIndex !== -1) {
      const raw = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);

      if (raw.length > 0) {
        const parsed = parseFrame(raw);
        if (isErrorMessage(parsed)) {
          stats.framesRejected += 1;
          send(socket, parsed);
        } else {
          // send_group legitimately exceeds the DM frame cap (up to 50
          // envelopes); everything else stays under the tight limit.
          const oversized =
            raw.length > MAX_FRAME_BYTES &&
            !(parsed.type === "send_group" && raw.length <= MAX_GROUP_FRAME_BYTES);
          if (oversized) {
            send(socket, errorMessage("TOO_LARGE", "frame too large"));
            socket.destroy();
            return;
          }
          try {
            handleMessage(socket, parsed);
          } catch (err) {
            stats.framesRejected += 1;
            logger.warn({ err: String(err) }, "message handler failed");
            send(socket, errorMessage("INVALID", "could not process frame"));
          }
        }
      }

      newlineIndex = buffer.indexOf("\n");
    }
  });
}

const server = tls.createServer({ ...loadTlsCredentials() }, onConnection);

server.on("tlsClientError", (err, socket) => {
  logger.warn({ err: String(err), ip: socket.remoteAddress ?? "unknown" }, "TLS handshake failed");
});
server.on("error", (err) => {
  logger.error({ err: String(err) }, "server error");
});

server.listen(PORT, "0.0.0.0", () => {
  logger.info(`yapr server listening on port ${PORT} (TLS)`);
});

// Heartbeat + idle sweep + limiter GC.
const heartbeat = setInterval(() => {
  const now = Date.now();
  for (const sock of connections.values()) {
    if (now - (sock.lastActivity ?? now) > IDLE_TIMEOUT_MS) {
      sock.destroy();
      continue;
    }
    send(sock, versioned({ type: "ping" }));
  }
  registerLimiter.sweep(now);
  sendLimiter.sweep(now);
  authLimiter.sweep(now);
  keysLimiter.sweep(now);
  groupLimiter.sweep(now);
}, PING_INTERVAL_MS);
heartbeat.unref();

// Reap expired dedup rows so processed_messages stays bounded.
const gc = setInterval(() => {
  try {
    const result = deleteProcessedOlderThanStmt.run(Date.now() - PROCESSED_TTL_MS) as {
      changes: number | bigint;
    };
    if (Number(result.changes) > 0) {
      logger.info({ reaped: Number(result.changes) }, "processed GC");
    }
  } catch (err) {
    logger.warn({ err: String(err) }, "processed GC failed");
  }
}, GC_INTERVAL_MS);
gc.unref();

// Periodic operational summary for platform logs.
const statsTimer = setInterval(() => {
  logger.info(
    {
      uptimeSec: Math.floor((Date.now() - stats.startedAt) / 1000),
      liveConnections: stats.liveConnections,
      pendingDepth: pendingDepth(),
      registered: stats.registered,
      identified: stats.identified,
      relayed: stats.relayed,
      acked: stats.acked,
      readsForwarded: stats.readsForwarded,
      keysServed: stats.keysServed,
      framesRejected: stats.framesRejected,
      groupsCreated: stats.groupsCreated,
      groupSends: stats.groupSends,
    },
    "server stats"
  );
}, STATS_INTERVAL_MS);
statsTimer.unref();

function shutdown(signal: string) {
  logger.info(`received ${signal}, shutting down...`);
  clearInterval(heartbeat);
  clearInterval(gc);
  clearInterval(statsTimer);
  server.close(() => {
    try {
      db.close();
    } catch {
      // Best effort: already closed.
    }
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 5000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
