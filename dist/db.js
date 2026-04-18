"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const better_sqlite3_1 = __importDefault(require("better-sqlite3"));
const node_path_1 = __importDefault(require("node:path"));
const node_fs_1 = __importDefault(require("node:fs"));
const dataDir = node_path_1.default.join(__dirname, "..", "data");
node_fs_1.default.mkdirSync(dataDir, { recursive: true });
const dbPath = node_path_1.default.join(dataDir, "yapr.db");
const db = new better_sqlite3_1.default(dbPath);
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS pending_messages (
    message_id TEXT PRIMARY KEY,
    client_message_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    UNIQUE (sender_id, client_message_id)
  );

  CREATE TABLE IF NOT EXISTS processed_messages (
    sender_id TEXT NOT NULL,
    client_message_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (sender_id, client_message_id)
  );

  CREATE INDEX IF NOT EXISTS idx_pending_recipient
  ON pending_messages (recipient_id);
`);
exports.default = db;
