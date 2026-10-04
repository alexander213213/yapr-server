import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import { dbPathFor, ensureDataDir } from "./storage.js";

const SCHEMA_VERSION = 4;

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
    pubkey TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS pending_messages (
    message_id TEXT PRIMARY KEY,
    client_message_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    group_id TEXT,
    ciphertext TEXT NOT NULL,
    nonce TEXT NOT NULL DEFAULT '',
    sender_timestamp INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    UNIQUE (sender_id, client_message_id, recipient_id)
  );

  CREATE TABLE IF NOT EXISTS groups (
    group_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    creator_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    joined_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    PRIMARY KEY (group_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS processed_messages (
    sender_id TEXT NOT NULL,
    client_message_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    PRIMARY KEY (sender_id, client_message_id, message_id)
  );

  CREATE INDEX IF NOT EXISTS idx_pending_recipient_created
  ON pending_messages (recipient_id, created_at, message_id);

  CREATE INDEX IF NOT EXISTS idx_processed_message_id
  ON processed_messages (message_id);
`);

const row = db
  .prepare(`SELECT version FROM schema_version ORDER BY version DESC LIMIT 1`)
  .get() as { version: number } | undefined;
let version: number;
if (!row) {
  db.prepare(`INSERT INTO schema_version (version) VALUES (?)`).run(SCHEMA_VERSION);
  version = SCHEMA_VERSION;
} else {
  version = row.version;
}

if (version === 1) {
  // v1 -> v2: hashed auth. Legacy rows keep the plaintext `secret` until the
  // next successful login transparently re-hashes them (see identifyUser).
  const cols = db.prepare(`PRAGMA table_info(users)`).all() as { name: string }[];
  if (!cols.some((c) => c.name === "secret_hash")) {
    db.exec(`ALTER TABLE users ADD COLUMN secret_hash TEXT`);
  }
  db.prepare(`UPDATE schema_version SET version = ?`).run(2);
  version = 2;
}

if (version === 2) {
  // v2 -> v3: relay-only opaque envelopes. One-time backup first (destructive rebuild).
  const backupPath = `${dbPath}.bak.v2.${Date.now()}`;
  fs.copyFileSync(dbPath, backupPath);
  console.log(`schema v2 backup at ${backupPath}`);

  const userCols = db.prepare(`PRAGMA table_info(users)`).all() as { name: string }[];
  if (!userCols.some((c) => c.name === "pubkey")) {
    db.exec(`ALTER TABLE users ADD COLUMN pubkey TEXT`);
  }

  // Convert surviving plaintext rows: ciphertext = base64(utf8 text), nonce = ''.
  // New clients treat empty nonce as "legacy plaintext, base64-decode" (see PROTOCOL-v2.md).
  type LegacyPending = {
    message_id: string;
    client_message_id: string;
    sender_id: string;
    recipient_id: string;
    text: string;
    created_at: number;
  };
  const legacy = db
    .prepare(
      `SELECT message_id, client_message_id, sender_id, recipient_id, text, created_at
       FROM pending_messages`
    )
    .all() as LegacyPending[];
  db.exec(`ALTER TABLE pending_messages RENAME TO pending_messages_v1`);
  db.exec(`
    CREATE TABLE pending_messages (
      message_id TEXT PRIMARY KEY,
      client_message_id TEXT NOT NULL,
      sender_id TEXT NOT NULL,
      recipient_id TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      nonce TEXT NOT NULL DEFAULT '',
      sender_timestamp INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      UNIQUE (sender_id, client_message_id)
    )
  `);
  const insertConverted = db.prepare(`
    INSERT INTO pending_messages
      (message_id, client_message_id, sender_id, recipient_id, ciphertext, nonce, sender_timestamp, created_at)
    VALUES (?, ?, ?, ?, ?, '', ?, ?)
  `);
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const m of legacy) {
      insertConverted.run(
        m.message_id,
        m.client_message_id,
        m.sender_id,
        m.recipient_id,
        Buffer.from(m.text, "utf8").toString("base64"),
        m.created_at,
        m.created_at
      );
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
  db.exec(`DROP TABLE pending_messages_v1`);
  db.prepare(`UPDATE schema_version SET version = ?`).run(SCHEMA_VERSION);
  version = SCHEMA_VERSION;
  console.log(`migrated ${legacy.length} pending rows to opaque envelopes`);
}

if (version === 3) {
  // v3 -> v4: groups + fan-out-safe dedup. Rebuilds pending (group_id column,
  // UNIQUE widened to per-recipient so one send can fan out to N rows) and
  // processed (PK widened likewise so every member's ack lands). Backup first.
  const backupPath = `${dbPath}.bak.v3.${Date.now()}`;
  fs.copyFileSync(dbPath, backupPath);
  console.log(`schema v3 backup at ${backupPath}`);

  type OldPending = {
    message_id: string;
    client_message_id: string;
    sender_id: string;
    recipient_id: string;
    ciphertext: string;
    nonce: string;
    sender_timestamp: number;
    created_at: number;
  };
  const pend = db
    .prepare(
      `SELECT message_id, client_message_id, sender_id, recipient_id,
              ciphertext, nonce, sender_timestamp, created_at
       FROM pending_messages`
    )
    .all() as OldPending[];
  type OldProcessed = {
    sender_id: string;
    client_message_id: string;
    message_id: string;
    created_at: number;
  };
  const proc = db
    .prepare(
      `SELECT sender_id, client_message_id, message_id, created_at
       FROM processed_messages`
    )
    .all() as OldProcessed[];

  db.exec(`ALTER TABLE pending_messages RENAME TO pending_messages_v3`);
  db.exec(`
    CREATE TABLE pending_messages (
      message_id TEXT PRIMARY KEY,
      client_message_id TEXT NOT NULL,
      sender_id TEXT NOT NULL,
      recipient_id TEXT NOT NULL,
      group_id TEXT,
      ciphertext TEXT NOT NULL,
      nonce TEXT NOT NULL DEFAULT '',
      sender_timestamp INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      UNIQUE (sender_id, client_message_id, recipient_id)
    )
  `);
  db.exec(`DROP TABLE processed_messages`);
  db.exec(`
    CREATE TABLE processed_messages (
      sender_id TEXT NOT NULL,
      client_message_id TEXT NOT NULL,
      message_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (sender_id, client_message_id, message_id)
    )
  `);
  const insertPend = db.prepare(`
    INSERT INTO pending_messages
      (message_id, client_message_id, sender_id, recipient_id, group_id,
       ciphertext, nonce, sender_timestamp, created_at)
    VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)
  `);
  const insertProc = db.prepare(`
    INSERT INTO processed_messages (sender_id, client_message_id, message_id, created_at)
    VALUES (?, ?, ?, ?)
  `);
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const m of pend) {
      insertPend.run(
        m.message_id, m.client_message_id, m.sender_id, m.recipient_id,
        m.ciphertext, m.nonce, m.sender_timestamp, m.created_at
      );
    }
    for (const m of proc) {
      insertProc.run(m.sender_id, m.client_message_id, m.message_id, m.created_at);
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
  db.exec(`DROP TABLE pending_messages_v3`);
  db.prepare(`UPDATE schema_version SET version = ?`).run(SCHEMA_VERSION);
  version = SCHEMA_VERSION;
  console.log(`migrated ${pend.length} pending + ${proc.length} processed rows to v4`);
}

if (version !== SCHEMA_VERSION) {
  throw new Error(
    `Unsupported schema version ${version} (expected ${SCHEMA_VERSION}). Refusing to open ${dbPath}.`
  );
}

// Indexes last: baseline tables may predate columns the indexes reference
// (migrations above bring them current first). IF NOT EXISTS keeps this
// idempotent for fresh databases and re-runs.
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_pending_recipient_created
  ON pending_messages (recipient_id, created_at, message_id);
  CREATE INDEX IF NOT EXISTS idx_pending_group
  ON pending_messages (recipient_id, group_id, created_at, message_id);
  CREATE INDEX IF NOT EXISTS idx_processed_sender_client
  ON processed_messages (sender_id, client_message_id);
  CREATE INDEX IF NOT EXISTS idx_group_members_user
  ON group_members (user_id, group_id);
  CREATE INDEX IF NOT EXISTS idx_processed_message_id
  ON processed_messages (message_id);
`);

console.log(`using data dir ${dataDir}`);

export default db;
