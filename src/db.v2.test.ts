import { beforeAll, describe, expect, it } from "vitest";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

// A v2 database. v2->v3 used to stamp v4 directly, skipping the v3->v4
// rebuild, then crash on `no such column: group_id`.
const DIR = path.join(os.tmpdir(), `yapr-server-db-v2-${process.pid}-${Date.now()}`);
fs.rmSync(DIR, { recursive: true, force: true });
fs.mkdirSync(DIR, { recursive: true });
process.env.YAPR_SERVER_DATA_DIR = DIR;

const seed = new DatabaseSync(path.join(DIR, "yapr.db"));
seed.exec(`
  CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
  INSERT INTO schema_version VALUES (2);
  CREATE TABLE users (user_id TEXT PRIMARY KEY, secret TEXT NOT NULL, secret_hash TEXT, created_at INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE pending_messages (
    message_id TEXT PRIMARY KEY, client_message_id TEXT NOT NULL, sender_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL, text TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE (sender_id, client_message_id)
  );
  CREATE TABLE processed_messages (
    sender_id TEXT NOT NULL, client_message_id TEXT NOT NULL, message_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (sender_id, client_message_id)
  );
  INSERT INTO pending_messages VALUES ('m1', 'c1', '111', '222', 'queued', 1700000000000);
  INSERT INTO processed_messages VALUES ('111', 'c0', 'm0', 1700000000000);
`);
seed.close();

let db: DatabaseSync;
beforeAll(async () => {
  // db.ts opens the DB on import, so import only after the seed above.
  db = ((await import("./db.js")) as unknown as { default: DatabaseSync }).default;
});

describe("v2 database", () => {
  it("opens at v4 with group fan-out keys", () => {
    expect((db.prepare(`SELECT version FROM schema_version`).get() as { version: number }).version).toBe(4);
    const pending = (db.prepare(`PRAGMA table_info(pending_messages)`).all() as { name: string }[]).map((c) => c.name);
    expect(pending).toContain("group_id");
    // One clientMessageId may now fan out to several recipients.
    db.prepare(
      `INSERT INTO pending_messages (message_id, client_message_id, sender_id, recipient_id, ciphertext, created_at)
       VALUES ('m2', 'c1', '111', '333', 'x', 1)`
    ).run();
  });

  it("carries pending and processed rows across", () => {
    const row = db.prepare(`SELECT ciphertext FROM pending_messages WHERE message_id = 'm1'`).get() as { ciphertext: string };
    expect(Buffer.from(row.ciphertext, "base64").toString("utf8")).toBe("queued");
    expect(db.prepare(`SELECT 1 FROM processed_messages WHERE message_id = 'm0'`).get()).toBeTruthy();
  });
});
