#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/certs"
CERT_FILE="${CERT_DIR}/server.crt"
KEY_FILE="${CERT_DIR}/server.key"
CONFIG_FILE="${CERT_DIR}/openssl.cnf"

mkdir -p "${CERT_DIR}"

if [[ -f "${CERT_FILE}" && -f "${KEY_FILE}" ]]; then
  echo "TLS certificate already exists: ${CERT_FILE}"
  exit 0
fi

cat > "${CONFIG_FILE}" <<'CONFIG'
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
CONFIG

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -keyout "${KEY_FILE}" \
  -out "${CERT_FILE}" \
  -days 365 \
  -config "${CONFIG_FILE}" >/dev/null 2>&1

chmod 600 "${KEY_FILE}" "${CERT_FILE}"
echo "TLS certificate generated: ${CERT_FILE}"
