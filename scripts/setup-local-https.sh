#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tls="$root/.local-dev/tls"
umask 077
mkdir -p "$tls"
if [[ -e "$tls/server.crt" || -e "$tls/server.key" ]]; then
  test -f "$tls/server.crt" && test -f "$tls/server.key"
  openssl x509 -in "$tls/server.crt" -checkend 86400 -noout
  test "$(openssl x509 -in "$tls/server.crt" -pubkey -noout | openssl sha256)" = "$(openssl pkey -in "$tls/server.key" -pubout | openssl sha256)"
  echo "Existing local certificate/key retained."
else
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
    -keyout "$tls/server.key" -out "$tls/server.crt" \
    -subj "/CN=InfraScope Local Development" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth"
fi
chmod 600 "$tls/server.key" "$tls/server.crt"
openssl x509 -in "$tls/server.crt" -noout -subject -dates -fingerprint -sha256
echo "Trust only this localhost server certificate in the current Windows user's Root store. Never copy the private key out of WSL."
