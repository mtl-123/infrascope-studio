#!/bin/sh
set -eu
umask 027
mkdir -p /var/log/infrascope
exec >> /var/log/infrascope/service.log 2>&1
printf '\n[%s] InfraScope %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${1:-serve}"
if [ "$#" -eq 0 ]; then set -- serve; fi
exec /app/infrascope "$@"
