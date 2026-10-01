import net from "node:net";
import tls from "node:tls";
import fs from "node:fs";
import crypto from "node:crypto";
import db from "./db.js";
import {
  AckMessage,
  ClientMessage,
  FetchKeysMessage,
  FetchPendingMessage,
  KeysResponse,
  PendingDone,
  ReadMessage,
  SendMessage,
  errorMessage,
  isErrorMessage,
  parseFrame,
  versioned,
} from "./protocol.js";
import {
  dummyCompare,
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

export type IncomingEnvelope = {
  v: 2;
  type: "incoming";
  messageId: string;
  from: string;
  ciphertext: string;
  nonce: string;
  timestamp: number;
};

export type ServerAckMessage = {
  v: 2;
  type: "server_ack";
  clientMessageId: string;
  messageId: string;
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
      (message_id, client_message_id, sender_id, recipient_id, ciphertext, nonce, sender_timestamp, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

const findFirstPageStmt = db.prepare(`
    SELECT message_id, client_message_id, sender_id, recipient_id, ciphertext, nonce, sender_timestamp, created_at
    FROM pending_messages
    WHERE recipient_id = ?
    ORDER BY created_at ASC, message_id ASC
    LIMIT ?
`);

const findNextPageStmt = db.prepare(`
    SELECT message_id, client_message_id, sender_id, recipient_id, ciphertext, nonce, sender_timestamp, created_at
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
`);

const findProcessedMessageByMessageIdStmt = db.prepare(`
    SELECT sender_id, client_message_id, message_id FROM processed_messages
    WHERE message_id = ?
`);

const deleteProcessedOlderThanStmt = db.prepare(`
    DELETE FROM processed_messages
    WHERE created_at < ?
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

  send(socket, versioned({
    type: "registered",
    userId,
    secret,
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
  sendPendingPage(socket);
  send(socket, versioned({
    type: "identified",
    userId,
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
  return versioned({
    type: "incoming",
    from: row.sender_id,
    messageId: row.message_id,
    ciphertext: row.ciphertext,
    nonce: row.nonce,
    timestamp: row.created_at,
  });
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
  const response: KeysResponse = versioned({ type: "keys", keys });
  send(socket, response);
}

function handleFetchPending(socket: AuthedSocket, message: FetchPendingMessage) {
  if (!socket.userId) return;
  sendPendingPage(socket, message.cursor, message.limit);
}

type EnvelopeRef = { message_id: string; client_message_id: string };

/** Idempotent send lookup, scoped to the sender. Stale dedup rows are reaped so
 *  a clientMessageId can be reused after the TTL expires. */
function findExistingEnvelope(
  senderId: string,
  clientMessageId: string
): EnvelopeRef | undefined {
  const pending = findPendingByClientMessageIdStmt.get(senderId, clientMessageId) as
    | EnvelopeRef
    | undefined;
  if (pending) return pending;
  const processed = findProcessedMessageByClientMessageIdStmt.get(senderId, clientMessageId) as
    | (ProcessedMessageRow & { created_at: number })
    | undefined;
  if (!processed) return undefined;
  if (Date.now() - processed.created_at < PROCESSED_TTL_MS) {
    return { message_id: processed.message_id, client_message_id: processed.client_message_id };
  }
  deleteProcessedByClientMessageIdStmt.run(senderId, clientMessageId);
  return undefined;
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
  const existing = findExistingEnvelope(senderId, message.clientMessageId);
  if (existing) {
    const ack: ServerAckMessage = versioned({
      type: "server_ack",
      clientMessageId: existing.client_message_id,
      messageId: existing.message_id,
      status: "accepted",
      timestamp: now,
    });
    send(socket, ack);
    return;
  }
  const messageId = generateMessageId();
  try {
    insertMessageStmt.run(
      messageId,
      message.clientMessageId,
      senderId,
      message.to,
      message.ciphertext,
      message.nonce,
      message.timestamp,
      now
    );
  } catch (err: unknown) {
    if ((err as { code?: string }).code === "SQLITE_CONSTRAINT_UNIQUE") {
      // Lost race with a concurrent identical send: answer from the stored row.
      const raced = findExistingEnvelope(senderId, message.clientMessageId);
      if (raced) {
        const ack: ServerAckMessage = versioned({
          type: "server_ack",
          clientMessageId: raced.client_message_id,
          messageId: raced.message_id,
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

  send(recipientSocket, payload);
}

function handleAck(socket: AuthedSocket, message: AckMessage) {
  if (!socket.userId) return;
  try {
    ackTx(message.messageId, socket.userId);
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
    case "pong":
      break;
  }
}

function onConnection(rawSocket: net.Socket) {
  rawSocket.setEncoding("utf8");
  const socket = rawSocket as AuthedSocket;
  socket.lastActivity = Date.now();
  let buffer = "";

  const authTimer = setTimeout(() => {
    if (!socket.userId) {
      send(socket, errorMessage("UNAUTH", "identify within 10s of connecting"));
      socket.destroy();
    }
  }, AUTH_TIMEOUT_MS);
  authTimer.unref();

  socket.once("close", () => clearTimeout(authTimer));
  socket.on("error", (err) => {
    logger.warn({ err: String(err), ip: clientIp(socket) }, "socket error");
  });

  socket.on("data", (chunk: string) => {
    socket.lastActivity = Date.now();
    buffer += chunk;

    if (buffer.length > MAX_FRAME_BYTES + 1024) {
      send(socket, errorMessage("TOO_LARGE", "frame too large"));
      socket.destroy();
      return;
    }

    let newlineIndex = buffer.indexOf("\n");

    while (newlineIndex !== -1) {
      const raw = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);

      if (raw.length > 0) {
        if (raw.length > MAX_FRAME_BYTES) {
          send(socket, errorMessage("TOO_LARGE", "frame too large"));
          socket.destroy();
          return;
        }
        const parsed = parseFrame(raw);
        if (isErrorMessage(parsed)) {
          send(socket, parsed);
        } else {
          try {
            handleMessage(socket, parsed);
          } catch (err) {
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

function shutdown(signal: string) {
  logger.info(`received ${signal}, shutting down...`);
  clearInterval(heartbeat);
  clearInterval(gc);
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
