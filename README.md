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

## Deploying

```bash
docker build -t yapr-server .
docker run -d --name yapr-server \
  -p 9000:9000 \
  -e PORT=9000 \
  -e TLS_CERT="$(cat fullchain.pem)" -e TLS_KEY="$(cat privkey.pem)" \
  -v yapr-data:/data \
  yapr-server
```

On Railway: use the Dockerfile (or `npm ci && npm run build` + `npm start`), attach a TCP
route to `PORT`, mount a volume at `/data` with `YAPR_SERVER_DATA_DIR=/data`, and provide
the cert as secret env vars. Back up `/data/yapr.db` before deploying a build that migrates
the schema (the server refuses to open newer-than-expected databases).

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
