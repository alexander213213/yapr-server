import { beforeAll, describe, expect, it } from "vitest";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

// The pre-versioning layout from the old dist/db.js: no schema_version.
// It used to be stamped current and skip every migration. Seeded BEFORE
// db.ts is imported (it opens the DB at import time).
const DIR = path.join(os.tmpdir(), `yapr-server-db-v1-${process.pid}-${Date.now()}`);
fs.rmSync(DIR, { recursive: true, force: true });
fs.mkdirSync(DIR, { recursive: true });
process.env.YAPR_SERVER_DATA_DIR = DIR;

const seed = new DatabaseSync(path.join(DIR, "yapr.db"));
seed.exec(`
  CREATE TABLE users (user_id TEXT PRIMARY KEY, secret TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE pending_messages (
    message_id TEXT PRIMARY KEY, client_message_id TEXT NOT NULL, sender_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL, text TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE (sender_id, client_message_id)
  );
  CREATE TABLE processed_messages (
    sender_id TEXT NOT NULL, client_message_id TEXT NOT NULL, message_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (sender_id, client_message_id)
  );
  INSERT INTO users (user_id, secret) VALUES ('111', 'legacy-plain');
  INSERT INTO pending_messages VALUES ('m1', 'c1', '111', '222', 'hi there', 1700000000);
`);
seed.close();

let db: DatabaseSync;
beforeAll(async () => {
  // db.ts opens the DB on import, so import only after the seed above.
  db = ((await import("./db.js")) as unknown as { default: DatabaseSync }).default;
});

describe("v1 (pre-versioning) database", () => {
  it("walks the whole chain to v4", () => {
    expect((db.prepare(`SELECT version FROM schema_version`).get() as { version: number }).version).toBe(4);
    const users = (db.prepare(`PRAGMA table_info(users)`).all() as { name: string }[]).map((c) => c.name);
    expect(users).toEqual(expect.arrayContaining(["secret_hash", "pubkey"]));
  });

  it("keeps the pending row as an opaque envelope with a group column", () => {
    const row = db.prepare(`SELECT * FROM pending_messages WHERE message_id = 'm1'`).get() as {
      ciphertext: string; nonce: string; group_id: string | null;
    };
    expect(Buffer.from(row.ciphertext, "base64").toString("utf8")).toBe("hi there");
    expect(row.nonce).toBe("");
    expect(row.group_id).toBeNull();
  });

  it("keeps the legacy user for transparent re-hash on login", () => {
    const user = db.prepare(`SELECT secret FROM users WHERE user_id = '111'`).get() as { secret: string };
    expect(user.secret).toBe("legacy-plain");
  });
});
