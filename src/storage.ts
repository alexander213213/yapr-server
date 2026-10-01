import os from "node:os";
import path from "node:path";
import fs from "node:fs";

export const APP_NAME = "yapr-server";
export const DB_FILENAME = "yapr.db";

/** Resolve the persistent data dir. Never points inside the installed package. */
export function resolveDataDir(): string {
  const override = process.env.YAPR_SERVER_DATA_DIR?.trim();
  if (override) return override;

  const home = os.homedir();
  switch (os.platform()) {
    case "win32": {
      const base =
        process.env.APPDATA || process.env.LOCALAPPDATA || path.join(home, "AppData", "Roaming");
      return path.join(base, APP_NAME);
    }
    case "darwin":
      return path.join(home, "Library", "Application Support", APP_NAME);
    default: {
      const xdg = process.env.XDG_DATA_HOME || path.join(home, ".local", "share");
      return path.join(xdg, APP_NAME);
    }
  }
}

/** Legacy v1 location inside the package dir (wiped on npm update). Kept for migration only. */
export function legacyDbPath(): string {
  return path.join(__dirname, "..", "data", DB_FILENAME);
}

export function dbPathFor(dataDir: string): string {
  return path.join(dataDir, DB_FILENAME);
}

/**
 * Ensure the data dir exists and migrate a legacy v1 DB once (copy, don't move).
 * Returns the resolved data dir.
 */
export function ensureDataDir(): string {
  const dir = resolveDataDir();
  fs.mkdirSync(dir, { recursive: true });

  const target = dbPathFor(dir);
  if (!fs.existsSync(target)) {
    const legacy = legacyDbPath();
    if (path.resolve(legacy) !== path.resolve(target) && fs.existsSync(legacy)) {
      fs.copyFileSync(legacy, target);
      console.log(`migrated legacy db ${legacy} -> ${target}`);
    }
  }
  return dir;
}
