#!/usr/bin/env node
// Docker HEALTHCHECK probe: TLS handshake + an auth-free pong frame.
// Exits 0 when the relay answers, 1 otherwise. No dependencies.
const tls = require("node:tls");

const host = process.env.HEALTH_HOST ?? "127.0.0.1";
const port = Number(process.env.PORT ?? "9000");

const socket = tls.connect({ host, port, rejectUnauthorized: false, timeout: 5000 }, () => {
  socket.write(JSON.stringify({ v: 2, type: "pong" }) + "\n");
  setTimeout(() => {
    socket.end();
    process.exit(0);
  }, 300);
});
socket.on("error", (err) => {
  console.error(`healthcheck failed: ${err.message}`);
  process.exit(1);
});
socket.setTimeout(5000, () => {
  console.error("healthcheck timed out");
  socket.destroy();
  process.exit(1);
});
