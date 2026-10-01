#!/usr/bin/env bash
# Generate self-signed dev certs for yapr-server (NOT for production).
# Usage: npm run certs
set -euo pipefail

OUT_DIR="${1:-certs}"
mkdir -p "$OUT_DIR"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found (git-bash on Windows ships it). Install openssl and retry." >&2
  exit 1
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/dev-key.pem" \
  -out "$OUT_DIR/dev-cert.pem" \
  -days 825 -sha256 \
  -subj "//CN=localhost" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

chmod 600 "$OUT_DIR/dev-key.pem" 2>/dev/null || true
echo "wrote $OUT_DIR/dev-cert.pem + $OUT_DIR/dev-key.pem"
