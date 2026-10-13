# yapr-server

Relay-only inbox for **yapr**, the terminal SMS-style messenger. Clients connect over
TLS, the server routes **opaque end-to-end encrypted envelopes** it cannot read, stores
them while recipients are offline, and deletes them once acknowledged.

## Features

- **Relay-only privacy** — message bodies are ciphertext + nonce blobs; the server only
  sees sender/recipient IDs for routing. Includes a public-key directory (`fetch_keys`)
  so clients can encrypt to each other.
- **SMS-style reliability** — offline inbox with at-least-once delivery, idempotent
  resends (same `clientMessageId` → same ack), keyset-paginated history sync,
  delivery acks and best-effort read receipts.
- **Hardened auth** — scrypt-hashed secrets with constant-time compare, identical
  responses for unknown users vs wrong passwords, per-IP login/register rate limits.
- **Abuse limits** — TLS-only (fail-closed, no plaintext mode), 10s auth timeout,
  heartbeat + idle sweep, 64KB frame cap, slow-consumer disconnects.
- **Durable storage** — SQLite in the OS data dir (survives npm updates), automatic
  schema migrations with pre-migration backups, hourly cleanup of old dedup rows.
- **Observable** — structured logs, per-minute stats summaries, Docker healthcheck.
- **Account recovery** — server-sealed bearer tokens let clients silently reclaim
  their user id after server data loss (fresh secret, normal login after).
  Set `YAPR_RECLAIM_KEY`; without it recovery is off. Group memberships are
  never restored from tokens — re-adding stays an admin action.

## Requirements

- Node.js ≥ 22
- A TLS certificate valid for the hostname clients dial (self-signed is fine for local dev)

## Quickstart (local)

```bash
npm ci
npm run certs        # self-signed localhost certs into ./certs (dev only, gitignored)
cp .env.example .env
npm run dev          # tsx with --env-file
```

In another terminal, run the checks:

```bash
npm run typecheck
npm test             # vitest unit tests
npm run build        # tsc into ./dist
npm start            # node dist/server.js (production entrypoint)
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `9000` | Listen port (Railway injects its own) |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | — | Cert + key paths (**or** inline `TLS_CERT` / `TLS_KEY` PEM). Required — boot fails without them |
| `YAPR_SERVER_DATA_DIR` | OS data dir | SQLite location. **Point at a volume (`/data`) in production** or data is lost on redeploy |
| `LOG_LEVEL` | `info` | pino log level |
| `MAX_FRAME_BYTES` | `65536` | Largest accepted protocol frame |
| `AUTH_TIMEOUT_MS` | `10000` | Time to identify before disconnect |
| `PING_INTERVAL_MS` / `IDLE_TIMEOUT_MS` | `30000` / `300000` | Heartbeat and idle sweep |
| `RATE_REGISTER_MAX` / `RATE_AUTH_MAX` / `RATE_SEND_MAX` / `RATE_KEYS_MAX` | `10` / `20` / `120` / `60` | Per-minute budgets (windows tunable via `*_WINDOW_MS`) |
| `PROCESSED_TTL_MS` | 30 days | Idempotent-resend horizon + dedup GC TTL |
| `STATS_INTERVAL_MS` | `60000` | Stats summary period |
| `YAPR_RECLAIM_KEY` | — | Base64 32B key for account-recovery tokens (see below). Unset = recovery off |

## Account recovery

If the database is lost (e.g. a deploy without the `/data` volume), clients
can silently reclaim their previous user id instead of forking to a new one —
contacts and history on other devices resolve again because ids anchor both.

How it works:

1. Set `YAPR_RECLAIM_KEY` to a base64 32-byte secret (generate with
   `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`)
   and back it up offsite alongside the TLS key. Every `register` and
   `identify` then returns a server-sealed bearer token the client stores.
2. On data loss, the client's next login is rejected, so it presents its token
   (`reclaim` frame). The server re-creates that id with a **fresh** secret,
   and the client logs in normally. No prompts, no manual steps.
3. Reclaim on an existing id is rejected, and the client never auto-registers
   a new id while it holds a token — a failed recovery stays visible until the
   operator is contacted, instead of silently forking identity.

Limits: the token is password-equivalent (whoever holds it claims the id on a
fresh server) — treat client backups as credentials. Group memberships are not
restored (a stale token must not re-admit a removed member); re-adding stays
an admin action. Messages in flight when the data was lost stay lost.

## Deploying

No Docker required. The default path is the platform buildpack (Railway, Render, plain VPS):

1. Build: `npm ci && npm run build`. Start: `npm start` (runs `node dist/server.js`).
   `engines` pins Node ≥ 22; `node:sqlite` is stdlib so there is no native toolchain step.
2. Attach a TCP route to `PORT` (the proxy passes raw bytes; the server terminates TLS, so
   the cert must be valid for the public hostname clients dial).
3. Mount persistent storage at `/data` and set `YAPR_SERVER_DATA_DIR=/data`. Without this,
   SQLite lives on the ephemeral filesystem and accounts + offline queue vanish on redeploy.
4. Provide the cert as secret env vars (inline `TLS_CERT`/`TLS_KEY` PEM is simplest).
5. Back up `/data/yapr.db` before deploying a build that migrates the schema (the server
   refuses to open newer-than-expected databases).

Prefer containers? A multi-stage `Dockerfile` is included (non-root `yapr` user, `/data`
volume preset, 30s TLS `HEALTHCHECK`):

```bash
docker build -f docker/Dockerfile -t yapr-server .
docker run -d --name yapr-server \
  -p 9000:9000 \
  -e PORT=9000 \
  -e TLS_CERT="$(cat fullchain.pem)" -e TLS_KEY="$(cat privkey.pem)" \
  -v yapr-data:/data \
  yapr-server
```

## Protocol (v2, breaking)

Framing is TLS + newline-delimited JSON, every frame carrying `v: 2`. Anything else gets
`UPGRADE_REQUIRED`.

| Direction | Frames |
|---|---|
| Client → server | `register{pubKey}`, `identify`, `fetch_keys`, `send{ciphertext,nonce}`, `ack`, `read`, `fetch_pending{cursor,limit}`, `pong` |
| Server → client | `registered`, `identified`, `keys`, `server_ack`, `incoming`, `pending_done{hasMore}`, `read_receipt`, `ping`, `error{code}` |

Errors are coded (`INVALID`, `UNAUTH`, `NOT_FOUND`, `RATE_LIMITED`, `TOO_LARGE`,
`UPGRADE_REQUIRED`) with generic messages. Legacy plaintext rows from v1 installs are
converted to base64 envelopes with an empty nonce, which clients decode as plaintext.

## Project layout

```
src/
  server.ts    TLS transport, connection lifecycle, relay handlers
  protocol.ts  zod-validated v2 frames + error codes
  auth.ts      scrypt hashing, key/ID generation
  limits.ts    token-bucket rate limiters + tunables
  storage.ts   OS data-dir resolution + legacy DB migration
  db.ts        node:sqlite open, pragmas, schema migrations
  logger.ts    pino instance
scripts/
  gen-dev-certs.sh   self-signed localhost certs (dev only)
  healthcheck.cjs    Docker HEALTHCHECK probe (TLS handshake + pong)
```

## License

ISC
