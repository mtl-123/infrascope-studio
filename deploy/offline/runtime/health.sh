#!/bin/sh
set -eu
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' |
  timeout 5 openssl s_client -connect 127.0.0.1:8443 -servername "${PUBLIC_HOST:-localhost}" \
    -CAfile /run/infrascope/tls/server.crt -verify_return_error -quiet 2>/dev/null |
  head -n 1 | grep -q ' 200 '
