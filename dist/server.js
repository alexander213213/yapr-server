"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_net_1 = __importDefault(require("node:net"));
const node_crypto_1 = __importStar(require("node:crypto"));
const db_1 = __importDefault(require("./db"));
const PORT = 9000;
const connections = new Map();
const insertUserStmt = db_1.default.prepare(`
    INSERT INTO users (user_id, secret)
    VALUES (?, ?)
`);
const findUserStmt = db_1.default.prepare(`
    SELECT user_id, secret, created_at
    FROM users
    WHERE user_id = ?
`);
const insertMessageStmt = db_1.default.prepare(`
    INSERT INTO pending_messages (message_Id, client_message_id, sender_id, recipient_id, text)
    VALUES (?, ?, ?, ?, ?)
`);
const findMessageByRecipientIdStmt = db_1.default.prepare(`
    SELECT * FROM pending_messages
    WHERE recipient_id = ?
`);
const findMessageByMessageIdStmt = db_1.default.prepare(`
    SELECT * FROM pending_messages
    WHERE message_id = ?
`);
const deleteMessageByMessageIdStmt = db_1.default.prepare(`
    DELETE FROM pending_messages
    WHERE message_id = ?
`);
const findMessageByClientMessageIdStmt = db_1.default.prepare(`
    SELECT * FROM pending_messages
    WHERE client_message_id = ? AND sender_id = ?
`);
const insertProcessedMessageStmt = db_1.default.prepare(`
    INSERT INTO processed_messages (message_id, client_message_id, sender_id)
    VALUES (?, ?, ?)
`);
const findProcessedMessageByClientMessageIdStmt = db_1.default.prepare(`
    SELECT * FROM processed_messages
    WHERE client_message_id = ? AND sender_id = ?
`);
const ackTx = db_1.default.transaction((messageId, userId) => {
    const pendingMsg = findMessageByMessageIdStmt.get(messageId);
    if (!pendingMsg)
        throw new Error("Unknown Ack");
    if (pendingMsg.recipient_id !== userId)
        throw new Error("Wrong messageId or userId");
    deleteMessageByMessageIdStmt.run(pendingMsg.message_id);
    insertProcessedMessageStmt.run(pendingMsg.message_id, pendingMsg.client_message_id, pendingMsg.sender_id);
});
function send(socket, payload) {
    socket.write(JSON.stringify(payload) + "\n");
}
function generateUserId() {
    while (true) {
        const userId = Math.floor(100000000000 + Math.random() * 900000000000).toString();
        const userExists = findUserStmt.get(userId);
        if (!userExists) {
            return userId;
        }
    }
}
function generateSecret() {
    return node_crypto_1.default.randomBytes(32).toString("hex");
}
function generateMessageId() {
    return (0, node_crypto_1.randomUUID)();
}
function registerUser(socket) {
    const userId = generateUserId();
    const secret = generateSecret();
    insertUserStmt.run(userId, secret);
    send(socket, {
        type: "registered",
        userId,
        secret,
    });
}
function identifyUser(socket, userId, secret) {
    const user = findUserStmt.get(userId);
    if (!user) {
        send(socket, {
            type: "error",
            message: "User not found",
        });
        return;
    }
    if (user.secret !== secret) {
        send(socket, {
            type: "error",
            message: "Invalid credentials",
        });
        return;
    }
    const authedSocket = socket;
    authedSocket.userId = userId;
    const userSocket = connections.get(userId);
    if (!!userSocket) {
        connections.delete(userId);
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
function sendPendingMessages(socket) {
    const pendingMessages = findMessageByRecipientIdStmt.all(socket.userId);
    if (pendingMessages.length === 0)
        return;
    for (let i = 0; i < pendingMessages.length; i++) {
        const pendingMessage = pendingMessages[i];
        const payload = {
            type: 'incoming_message',
            from: pendingMessage.sender_id,
            messageId: pendingMessage.message_id,
            text: pendingMessage.text,
            timestamp: pendingMessage.created_at
        };
        send(socket, payload);
    }
}
function relayMessage(socket, message) {
    if (!socket.userId)
        return;
    const recipient = findUserStmt.get(message.to);
    if (!recipient) {
        sendError(socket, "Recipient doesn't exist");
        return;
    }
    const messageId = generateMessageId();
    const msg_exist = isMessageStored(socket, message.clientMessageId);
    const idempotencytAck = {
        type: "server_ack",
        messageId: msg_exist?.message_id,
        clientMessageId: msg_exist?.client_message_id,
        status: "accepted"
    };
    if (msg_exist) {
        send(socket, idempotencytAck);
        return;
    }
    try {
        insertMessageStmt.run(messageId, message.clientMessageId, socket.userId, message.to, message.text);
    }
    catch (err) {
        if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
            send(socket, idempotencytAck);
            return;
        }
        throw err;
    }
    const ack = {
        type: "server_ack",
        clientMessageId: message.clientMessageId,
        messageId,
        status: "accepted"
    };
    send(socket, ack);
    const recipientSocket = connections.get(message.to);
    if (!recipientSocket)
        return;
    const payload = {
        type: "incoming_message",
        from: socket.userId,
        messageId,
        text: message.text,
        timestamp: Date.now()
    };
    send(recipientSocket, payload);
}
function handleAck(socket, message) {
    if (!socket.userId)
        return;
    try {
        ackTx(message.messageId, socket.userId);
    }
    catch (err) {
        sendError(socket, "Ack failed");
    }
}
function handleMessage(socket, message) {
    switch (message.type) {
        case "register":
            registerUser(socket);
            break;
        case "identify":
            identifyUser(socket, message.userId, message.secret);
            break;
        case "send_message":
            relayMessage(socket, message);
            break;
        case "delivery_ack":
            handleAck(socket, message);
            break;
        default:
            sendError(socket, "Unknown message type");
    }
}
function sendError(socket, message) {
    send(socket, {
        type: "error",
        message
    });
}
function isMessageStored(socket, clientMessageId) {
    const pendingMsg = findMessageByClientMessageIdStmt.get(clientMessageId, socket.userId);
    const processedMsg = findProcessedMessageByClientMessageIdStmt.get(clientMessageId, socket.userId);
    if (!pendingMsg && !processedMsg) {
        return undefined;
    }
    else if (processedMsg) {
        return processedMsg;
    }
    else {
        return pendingMsg;
    }
}
const server = node_net_1.default.createServer((rawSocket) => {
    rawSocket.setEncoding("utf8");
    const authedSocket = rawSocket;
    let buffer = "";
    authedSocket.on("data", (chunk) => {
        buffer += chunk;
        let newlineIndex = buffer.indexOf("\n");
        while (newlineIndex !== -1) {
            const raw = buffer.slice(0, newlineIndex).trim();
            buffer = buffer.slice(newlineIndex + 1);
            if (raw.length > 0) {
                try {
                    const parsed = JSON.parse(raw);
                    handleMessage(authedSocket, parsed);
                }
                catch {
                    send(authedSocket, {
                        type: "error",
                        message: "Invalid JSON",
                    });
                }
            }
            newlineIndex = buffer.indexOf("\n");
        }
    });
    authedSocket.on("error", () => { });
});
server.listen(PORT, () => {
    console.log(`yapr server listening on port ${PORT}`);
});
