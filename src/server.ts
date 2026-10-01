import net from "node:net";
import tls from "node:tls";
import fs from "node:fs";
import crypto from "node:crypto";
import db from "./db.js";
import {
  ClientMessage,
  DeliveryAckMessage,
  SendMessage,
  errorMessage,
  isErrorMessage,
  parseFrame,
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

export type IncomingMessage = {
  type: "incoming_message";
  messageId: string;
  from: string;
  text: string;
  timestamp: number;
};

export type ServerAckMessage = {
  type: "server_ack";
  clientMessageId: string;
  messageId: string;
  status: "accepted";
  timestamp: number;
};

type AuthedSocket = net.Socket & {
  userId?: string;
  lastActivity?: number;
};

type UserRow = {
  user_id: string;
  secret: string;
  secret_hash: string | null;
  created_at: number;
};

type MessageRow = {
  message_id: string;
  client_message_id: string;
  sender_id: string;
  recipient_id: string;
  text: string;
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

const insertUserStmt = db.prepare(`
    INSERT INTO users (user_id, secret, secret_hash)
    VALUES (?, ?, ?)
`);

const findUserStmt = db.prepare(`
    SELECT user_id, secret, secret_hash, created_at
    FROM users
    WHERE user_id = ?
`);

const updateSecretHashStmt = db.prepare(`
    UPDATE users SET secret = '', secret_hash = ?
    WHERE user_id = ?
`);

const insertMessageStmt = db.prepare(`
    INSERT INTO pending_messages (message_Id, client_message_id, sender_id, recipient_id, text, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
`);

const findMessageByRecipientIdStmt = db.prepare(`
    SELECT * FROM pending_messages
    WHERE recipient_id = ?
`);

const findMessageByMessageIdStmt = db.prepare(`
    SELECT * FROM pending_messages
    WHERE message_id = ?
`);

const deleteMessageByMessageIdStmt = db.prepare(`
    DELETE FROM pending_messages
    WHERE message_id = ?
`);

const findMessageByClientMessageIdStmt = db.prepare(`
    SELECT * FROM pending_messages
    WHERE client_message_id = ? AND sender_id = ?
`);

const insertProcessedMessageStmt = db.prepare(`
    INSERT INTO processed_messages (message_id, client_message_id, sender_id)
    VALUES (?, ?, ?)
`);

const deleteProcessedMessageByClientMessageIdStmt = db.prepare(`
    DELETE FROM processed_messages
    WHERE client_message_id = ?
`);

const findProcessedMessageByClientMessageIdStmt = db.prepare(`
    SELECT * FROM processed_messages
    WHERE client_message_id = ? AND sender_id = ?
`);

// node:sqlite has no db.transaction() helper (unlike better-sqlite3),
// so the ack delete+insert is wrapped in explicit BEGIN/COMMIT.
function ackTx(messageId: string, userId: string) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const pendingMsg = findMessageByMessageIdStmt.get(messageId) as MessageRow | undefined;

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

function registerUser(socket: AuthedSocket) {
  let userId: string;
  try {
    userId = generateUserId((id) => findUserStmt.get(id) !== undefined);
  } catch {
    send(socket, errorMessage("INVALID", "registration failed, retry"));
    return;
  }
  const secret = generateSecret();
  insertUserStmt.run(userId, "", hashSecret(secret));

  send(socket, {
    type: "registered",
    userId,
    secret,
  });
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
  sendPendingMessages(socket);
  send(socket, {
    type: "identified",
    userId,
  });
  socket.once("close", () => {
    const current = connections.get(userId);
    if (current === socket) {
      connections.delete(userId);
    }
  });
}

function sendPendingMessages(socket: AuthedSocket) {
  if (!socket.userId) return;
  const pendingMessages = findMessageByRecipientIdStmt.all(socket.userId) as MessageRow[];
  if (pendingMessages.length === 0) return;
  for (let i = 0; i < pendingMessages.length; i++) {
    const pendingMessage = pendingMessages[i];
    if (!pendingMessage) continue;
    const payload: IncomingMessage = {
      type: "incoming_message",
      from: pendingMessage.sender_id,
      messageId: pendingMessage.message_id,
      text: pendingMessage.text,
      timestamp: pendingMessage.created_at,
    };
    if (!send(socket, payload)) return;
  }
}

function relayMessage(socket: AuthedSocket, message: SendMessage) {
  if (!socket.userId) return;
  const recipient = findUserStmt.get(message.to) as UserRow | undefined;
  if (!recipient) {
    send(socket, errorMessage("NOT_FOUND", "recipient not found"));
    return;
  }
  const messageId = generateMessageId();
  const msg_exist = isMessageStored(socket, message.clientMessageId);
  // NOTE (M2 will rewrite): this idempotency path is known-broken when the
  // stored row is missing fields. Kept behavior-identical for M1; only the
  // over-narrow Partial<ServerAckMessage> annotation is dropped for typecheck.
  const idempotencytAck = {
    type: "server_ack" as const,
    messageId: msg_exist?.message_id,
    clientMessageId: msg_exist?.client_message_id,
    status: "accepted" as const,
  };
  if (msg_exist) {
    send(socket, idempotencytAck);
    return;
  }
  const now = Date.now();
  try {
    insertMessageStmt.run(
      messageId,
      message.clientMessageId,
      socket.userId,
      message.to,
      message.text,
      now
    );
  } catch (err: unknown) {
    if ((err as { code?: string }).code === "SQLITE_CONSTRAINT_UNIQUE") {
      send(socket, idempotencytAck);
      return;
    }
    throw err;
  }
  const ack: ServerAckMessage = {
    type: "server_ack",
    clientMessageId: message.clientMessageId,
    messageId,
    status: "accepted",
    timestamp: now,
  };
  send(socket, ack);

  const recipientSocket = connections.get(message.to);

  if (!recipientSocket) return;
  const payload: IncomingMessage = {
    type: "incoming_message",
    from: socket.userId,
    messageId,
    text: message.text,
    timestamp: Date.now(),
  };

  send(recipientSocket, payload);
}

function handleAck(socket: AuthedSocket, message: DeliveryAckMessage) {
  if (!socket.userId) return;
  try {
    ackTx(message.messageId, socket.userId);
  } catch {
    send(socket, errorMessage("INVALID", "ack failed"));
  }
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
      registerUser(socket);
      break;

    case "identify":
      if (!authLimiter.take(ip)) {
        send(socket, errorMessage("RATE_LIMITED", "too many login attempts"));
        return;
      }
      identifyUser(socket, message.userId, message.secret);
      break;

    case "send_message":
      if (!requireAuth(socket)) return;
      if (!sendLimiter.take(socket.userId)) {
        send(socket, errorMessage("RATE_LIMITED", "sending too fast"));
        return;
      }
      relayMessage(socket, message);
      break;
    case "delivery_ack":
      if (!requireAuth(socket)) return;
      handleAck(socket, message);
      break;
    case "pong":
      break;
  }
}

function isMessageStored(socket: AuthedSocket, clientMessageId: string) {
  if (!socket.userId) return undefined;
  const userId: string = socket.userId;
  const pendingMsg = findMessageByClientMessageIdStmt.get(clientMessageId, userId) as
    | MessageRow
    | undefined;
  const processedMsg = findProcessedMessageByClientMessageIdStmt.get(clientMessageId, userId) as
    | ProcessedMessageRow
    | undefined;
  if (!pendingMsg && !processedMsg) {
    return undefined;
  } else if (processedMsg && Date.now() - processedMsg.created_at < 86_400_000) {
    return processedMsg!;
  } else {
    deleteProcessedMessageByClientMessageIdStmt.run(clientMessageId);
    return pendingMsg!;
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
    send(sock, { type: "ping" });
  }
  registerLimiter.sweep(now);
  sendLimiter.sweep(now);
  authLimiter.sweep(now);
}, PING_INTERVAL_MS);
heartbeat.unref();

function shutdown(signal: string) {
  logger.info(`received ${signal}, shutting down...`);
  clearInterval(heartbeat);
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
