/**
 * node:sqlite reports constraint violations via numeric `errcode`
 * (better-sqlite3 used string `code`, which never fires here).
 * Extended codes: SQLITE_CONSTRAINT_UNIQUE 2067, SQLITE_CONSTRAINT_PRIMARYKEY 1555.
 * Both mean "this row already exists" — the retry/idempotency signal.
 */
export const SQLITE_CONSTRAINT_UNIQUE = 2067;
export const SQLITE_CONSTRAINT_PRIMARYKEY = 1555;

export function isUniqueViolation(err: unknown): boolean {
  const e = err as { code?: string; errcode?: number } | null | undefined;
  return (
    e?.code === "SQLITE_CONSTRAINT_UNIQUE" ||
    e?.errcode === SQLITE_CONSTRAINT_UNIQUE ||
    e?.errcode === SQLITE_CONSTRAINT_PRIMARYKEY
  );
}
