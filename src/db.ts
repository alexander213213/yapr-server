import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import { dbPathFor, ensureDataDir } from "./storage.js";

const SCHEMA_VERSION = 2;

const dataDir = ensureDataDir();
const dbPath = dbPathFor(dataDir);
const isNewFile = !fs.existsSync(dbPath);

const db = new DatabaseSync(dbPath);

if (isNewFile) {
  try {
    fs.chmodSync(dbPath, 0o600);
  } catch {
    // Windows / read-only FS: best effort only.
  }
}

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA busy_timeout = 5000;
  PRAGMA synchronous = NORMAL;
  PRAGMA foreign_keys = ON;
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
  );

  CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    secret_hash TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS pending_messages (
    message_id TEXT PRIMARY KEY,
    client_message_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    UNIQUE (sender_id, client_message_id)
  );

  CREATE TABLE IF NOT EXISTS processed_messages (
    sender_id TEXT NOT NULL,
    client_message_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    PRIMARY KEY (sender_id, client_message_id)
  );

  CREATE INDEX IF NOT EXISTS idx_pending_recipient
  ON pending_messages (recipient_id);
`);

const row = db
  .prepare(`SELECT version FROM schema_version ORDER BY version DESC LIMIT 1`)
  .get() as { version: number } | undefined;
if (!row) {
  db.prepare(`INSERT INTO schema_version (version) VALUES (?)`).run(SCHEMA_VERSION);
} else if (row.version === 1) {
  // v1 -> v2: hashed auth. Legacy rows keep the plaintext `secret` until the
  // next successful login transparently re-hashes them (see identifyUser).
  const cols = db.prepare(`PRAGMA table_info(users)`).all() as { name: string }[];
  if (!cols.some((c) => c.name === "secret_hash")) {
    db.exec(`ALTER TABLE users ADD COLUMN secret_hash TEXT`);
  }
  db.prepare(`UPDATE schema_version SET version = ?`).run(SCHEMA_VERSION);
} else if (row.version !== SCHEMA_VERSION) {
  throw new Error(
    `Unsupported schema version ${row.version} (expected ${SCHEMA_VERSION}). Refusing to open ${dbPath}.`
  );
}

console.log(`using data dir ${dataDir}`);

export default db;
