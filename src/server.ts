import net from "node:net";
import crypto, { randomUUID } from "node:crypto";
import db from "./db";
import "dotenv/config"


type RegisterMessage = {
    type: "register";
};

type IdentifyMessage = {
    type: "identify";
    userId: string;
    secret: string;
};

type SendMessage = {
    type: "send_message";
    clientMessageId: string
    to: string
    text: string
}

type IncomingMessage = {
    type: "incoming_message"
    messageId: string
    from: string
    text: string
    timestamp: number
}

type DeliveryAckMessage = {
    type: "delivery_ack"
    messageId: string
}

type ServerAckMessage = {
    type: "server_ack"
    clientMessageId: string
    messageId: string
    status: "accepted"
}

type AuthedSocket = net.Socket & { userId?: string }

type ClientMessage = RegisterMessage | IdentifyMessage | SendMessage | DeliveryAckMessage;
type ServerMessage = IncomingMessage | ServerAckMessage

type UserRow = {
    user_id: string;
    secret: string;
    created_at: number;
};

type MessageRow = {
    message_id: string
    client_message_id: string
    sender_id: string
    recipient_id: string
    text: string
    created_at: number
}

type ProcessedMessageRow = {
    message_id: string
    client_message_id: string
    sender_id: string
    created_at: number
}

if (!process.env.PORT) {
  throw new Error("PORT is not defined");
}

const PORT = Number(process.env.PORT) || 9000;
const connections = new Map<string, AuthedSocket>();

const insertUserStmt = db.prepare(`
    INSERT INTO users (user_id, secret)
    VALUES (?, ?)
`);

const findUserStmt = db.prepare(`
    SELECT user_id, secret, created_at
    FROM users
    WHERE user_id = ?
`);

const insertMessageStmt = db.prepare(`
    INSERT INTO pending_messages (message_Id, client_message_id, sender_id, recipient_id, text)
    VALUES (?, ?, ?, ?, ?)
`)

const findMessageByRecipientIdStmt = db.prepare(`
    SELECT * FROM pending_messages
    WHERE recipient_id = ?
`)

const findMessageByMessageIdStmt = db.prepare(`
    SELECT * FROM pending_messages
    WHERE message_id = ?
`)

const deleteMessageByMessageIdStmt = db.prepare(`
    DELETE FROM pending_messages
    WHERE message_id = ?
`)

const findMessageByClientMessageIdStmt = db.prepare(`
    SELECT * FROM pending_messages
    WHERE client_message_id = ? AND sender_id = ?
`)

const insertProcessedMessageStmt = db.prepare(`
    INSERT INTO processed_messages (message_id, client_message_id, sender_id)
    VALUES (?, ?, ?)
`)

const deleteProcessedMessageByClientMessageIdStmt = db.prepare(`
    DELETE FROM processed_messages
    WHERE client_message_id = ?
`)

const findProcessedMessageByClientMessageIdStmt = db.prepare(`
    SELECT * FROM processed_messages
    WHERE client_message_id = ? AND sender_id = ?
`)

const ackTx = db.transaction((messageId: string, userId: string) => {
    const pendingMsg = findMessageByMessageIdStmt.get(messageId) as MessageRow | undefined;

    if (!pendingMsg) throw new Error("Unknown Ack");
    if (pendingMsg.recipient_id !== userId) throw new Error("Wrong messageId or userId");

    deleteMessageByMessageIdStmt.run(pendingMsg.message_id);
    insertProcessedMessageStmt.run(
        pendingMsg.message_id,
        pendingMsg.client_message_id,
        pendingMsg.sender_id
    );
});

function send(socket: net.Socket, payload: unknown) {
    socket.write(JSON.stringify(payload) + "\n");
}

function generateUserId() {
    while (true) {
        const userId = Math.floor(100_000_000_000 + Math.random() * 900_000_000_000).toString()
        const userExists = findUserStmt.get(userId)
        if (!userExists) {
            return userId
        }
    }
}

function generateSecret() {
    return crypto.randomBytes(32).toString("hex");
}

function generateMessageId() {
    return randomUUID()
}

function registerUser(socket: AuthedSocket) {
    const userId = generateUserId();
    const secret = generateSecret();

    insertUserStmt.run(userId, secret);

    send(socket, {
        type: "registered",
        userId,
        secret,
    });
}

function identifyUser(socket: AuthedSocket, userId: string, secret: string) {
    const user = findUserStmt.get(userId) as UserRow | undefined;

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
    const authedSocket = socket as AuthedSocket
    authedSocket.userId = userId
    const userSocket = connections.get(userId)
    if (!!userSocket) {
        connections.delete(userId)
        userSocket.end()
    }
    connections.set(userId, authedSocket);
    sendPendingMessages(socket)
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
    const pendingMessages = findMessageByRecipientIdStmt.all(socket.userId) as MessageRow[]
    if (pendingMessages.length === 0) return
    for (let i = 0; i < pendingMessages.length; i++) {
        const pendingMessage = pendingMessages[i]
        const payload: IncomingMessage = {
            type: 'incoming_message',
            from: pendingMessage.sender_id,
            messageId: pendingMessage.message_id,
            text: pendingMessage.text,
            timestamp: pendingMessage.created_at
        }
        send(socket, payload)
    }
}


function relayMessage(socket: AuthedSocket, message: SendMessage) {
    if (!socket.userId) return
    const recipient = findUserStmt.get(message.to) as UserRow | undefined
    if (!recipient) {
        sendError(socket, "Recipient doesn't exist")
        return
    }
    const messageId = generateMessageId()
    const msg_exist = isMessageStored(socket, message.clientMessageId)
    const idempotencytAck: Partial<ServerAckMessage> = {
        type: "server_ack",
        messageId: msg_exist?.message_id,
        clientMessageId: msg_exist?.client_message_id,
        status: "accepted"
    }
    if (msg_exist) {
        send(socket, idempotencytAck)
        return
    }
    try {
        insertMessageStmt.run(messageId, message.clientMessageId, socket.userId, message.to, message.text)
    } catch (err: any) {
        if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
            send(socket, idempotencytAck)
            return
        }
        throw err
    }

    const ack: ServerAckMessage = {
        type: "server_ack",
        clientMessageId: message.clientMessageId,
        messageId,
        status: "accepted"
    }
    send(socket, ack)

    const recipientSocket = connections.get(message.to)

    if (!recipientSocket) return
    const payload: IncomingMessage = {
        type: "incoming_message",
        from: socket.userId,
        messageId,
        text: message.text,
        timestamp: Date.now()
    }

    send(recipientSocket, payload)
}

function handleAck(socket: AuthedSocket, message: DeliveryAckMessage) {
    if (!socket.userId) return
    try {
        ackTx(message.messageId, socket.userId);
    } catch (err) {
        sendError(socket, "Ack failed");
    }
}

function handleMessage(socket: AuthedSocket, message: ClientMessage) {
    switch (message.type) {
        case "register":
            registerUser(socket);
            break;

        case "identify":
            identifyUser(socket, message.userId, message.secret);
            break;

        case "send_message":
            relayMessage(socket, message)
            break
        case "delivery_ack":
            handleAck(socket, message)
            break
        default:
            sendError(socket, "Unknown message type")
    }
}

function sendError(socket: AuthedSocket, message: string) {
    send(socket, {
        type: "error",
        message
    })
}

function isMessageStored(socket: AuthedSocket, clientMessageId: string) {
    const pendingMsg = findMessageByClientMessageIdStmt.get(clientMessageId, socket.userId) as MessageRow | undefined
    const processedMsg = findProcessedMessageByClientMessageIdStmt.get(clientMessageId, socket.userId) as ProcessedMessageRow | undefined
    if (!pendingMsg && !processedMsg) {
        return undefined
    } else if (processedMsg && (Date.now() - processedMsg.created_at) < 86_400_000) {
        return processedMsg!
    } else {
        deleteProcessedMessageByClientMessageIdStmt.run(clientMessageId)
        return pendingMsg!
    }

}

const server = net.createServer((rawSocket) => {
    rawSocket.setEncoding("utf8");
    const authedSocket = rawSocket as AuthedSocket
    let buffer = "";

    authedSocket.on("data", (chunk: string) => {
        buffer += chunk;

        let newlineIndex = buffer.indexOf("\n");

        while (newlineIndex !== -1) {
            const raw = buffer.slice(0, newlineIndex).trim();
            buffer = buffer.slice(newlineIndex + 1);

            if (raw.length > 0) {
                try {
                    const parsed = JSON.parse(raw) as ClientMessage;
                    handleMessage(authedSocket, parsed);
                } catch {
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

server.listen(PORT, "0.0.0.0", () => {
    console.log(`yapr server listening on port ${PORT}`);
});