import { describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import {
  SQLITE_CONSTRAINT_PRIMARYKEY,
  SQLITE_CONSTRAINT_UNIQUE,
  isUniqueViolation,
} from "./sqlite.js";

function duplicatePrimaryKey(): unknown {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(`CREATE TABLE t (id TEXT PRIMARY KEY, v TEXT)`);
    db.prepare(`INSERT INTO t (id, v) VALUES (?, ?)`).run("a", "1");
    db.prepare(`INSERT INTO t (id, v) VALUES (?, ?)`).run("a", "2");
    return null;
  } catch (err) {
    return err;
  } finally {
    db.close();
  }
}

function duplicateUniqueIndex(): unknown {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(`CREATE TABLE t (id TEXT PRIMARY KEY, v TEXT UNIQUE)`);
    db.prepare(`INSERT INTO t (id, v) VALUES (?, ?)`).run("a", "1");
    db.prepare(`INSERT INTO t (id, v) VALUES (?, ?)`).run("b", "1");
    return null;
  } catch (err) {
    return err;
  } finally {
    db.close();
  }
}

describe("isUniqueViolation", () => {
  it("recognizes a primary-key duplicate (errcode 1555)", () => {
    const err = duplicatePrimaryKey();
    expect(err).not.toBeNull();
    expect((err as { errcode?: number }).errcode).toBe(SQLITE_CONSTRAINT_PRIMARYKEY);
    expect(isUniqueViolation(err)).toBe(true);
  });

  it("recognizes a unique-index duplicate (errcode 2067)", () => {
    const err = duplicateUniqueIndex();
    expect(err).not.toBeNull();
    expect((err as { errcode?: number }).errcode).toBe(SQLITE_CONSTRAINT_UNIQUE);
    expect(isUniqueViolation(err)).toBe(true);
  });

  it("still recognizes the legacy string code", () => {
    expect(isUniqueViolation({ code: "SQLITE_CONSTRAINT_UNIQUE" })).toBe(true);
  });

  it("rejects unrelated errors", () => {
    expect(isUniqueViolation(new Error("nope"))).toBe(false);
    expect(isUniqueViolation(null)).toBe(false);
    expect(isUniqueViolation(undefined)).toBe(false);
  });
});
