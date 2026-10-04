#!/usr/bin/env bash
# Generate self-signed certs for yapr-server (dev/staging only — NOT production PKI).
# Usage:
#   npm run certs                                             # localhost-only (dev)
#   CERT_SANS="DNS:example.proxy.rlwy.net,DNS:localhost,IP:127.0.0.1" npm run certs
#                                                             # staging: valid for a public
#                                                             # hostname so clients can verify
#                                                             # it via YAPR_CA_FILE.
set -euo pipefail

OUT_DIR="${1:-certs}"
CERT_SANS="${CERT_SANS:-IP:127.0.0.1,DNS:localhost}"
mkdir -p "$OUT_DIR"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found (git-bash on Windows ships it). Install openssl and retry." >&2
  exit 1
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/dev-key.pem" \
  -out "$OUT_DIR/dev-cert.pem" \
  -days 825 -sha256 \
  -subj "//CN=yapr-relay" \
  -addext "subjectAltName=${CERT_SANS}"

chmod 600 "$OUT_DIR/dev-key.pem" 2>/dev/null || true
echo "wrote $OUT_DIR/dev-cert.pem + $OUT_DIR/dev-key.pem (SANs: ${CERT_SANS})"
