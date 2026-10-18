#!/bin/sh
# Runs as root only in a short-lived, network-disabled initialization container.
set -eu
umask 077
host=$1
port=$2
host_uid=$3
host_gid=$4
postgres_uid=$5
project=$6
bind_address=$7
for number in "$port" "$host_uid" "$host_gid" "$postgres_uid"; do
  case "$number" in ''|*[!0-9]*) echo 'Invalid numeric setting' >&2; exit 2;; esac
done
[ "$port" -ge 1 ] && [ "$port" -le 65535 ]
printf '%s' "$host" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]$|^[A-Za-z0-9]$'
printf '%s' "$project" | grep -Eq '^[a-z][a-z0-9_-]{0,50}$'
case "$bind_address" in 127.0.0.1|0.0.0.0) :;; *) exit 2;; esac
mkdir -p /config /logs/app /logs/postgres
for file in app.env postgres.env deploy.env admin.json; do
  [ ! -L "/config/$file" ] || { echo 'Refusing a configuration symlink' >&2; exit 2; }
done
if [ -e /config/app.env ] || [ -e /config/admin.json ] || [ -e /config/postgres.env ] || [ -e /config/deploy.env ]; then
  for file in app.env postgres.env deploy.env admin.json tls/server.crt tls/server.key; do
    [ -s "/config/$file" ] || { echo 'Incomplete configuration. Restore matching original config and encryption keys; nothing was regenerated.' >&2; exit 2; }
  done
  app_uid=$(sed -n 's/^APP_UID=//p' /config/deploy.env)
  app_gid=$(sed -n 's/^APP_GID=//p' /config/deploy.env)
  for number in "$app_uid" "$app_gid"; do case "$number" in ''|*[!0-9]*) exit 2;; esac; done
  echo 'Existing passwords, encryption keys and TLS certificate retained.'
else
  app_uid=$host_uid
  app_gid=$host_gid
  if [ "$app_uid" -eq 0 ]; then app_uid=10001; app_gid=10001; fi
  mkdir -p /config/tls
  if [ -e /config/tls/server.crt ] || [ -e /config/tls/server.key ]; then
    [ -s /config/tls/server.crt ] && [ -s /config/tls/server.key ] || { echo 'Restore the TLS certificate/key pair' >&2; exit 2; }
  else
    case "$host" in *[!0-9.]* ) target_san="DNS:$host";; *) target_san="IP:$host";; esac
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
      -keyout /config/tls/server.key -out /config/tls/server.crt \
      -subj '/CN=InfraScope Offline Deployment' \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,$target_san" \
      -addext 'basicConstraints=critical,CA:FALSE' -addext 'extendedKeyUsage=serverAuth' >/dev/null 2>&1
  fi
  database_password=$(openssl rand -hex 32)
  encryption_key=$(openssl rand -base64 32 | tr -d '\n')
  administrator_password=$(openssl rand -base64 24 | tr '/+' '_-' | tr -d '=\n')
  origin="https://$host:$port"
  [ "$port" -ne 443 ] || origin="https://$host"
  cat > /config/postgres.env <<EOF
POSTGRES_DB=infrascope
POSTGRES_USER=postgres
POSTGRES_PASSWORD=$database_password
EOF
  cat > /config/app.env <<EOF
REMOTE_ENABLED=true
REMOTE_LISTEN=0.0.0.0:8443
REMOTE_PUBLIC_ORIGIN=$origin
REMOTE_STATIC_DIR=/app/web
REMOTE_TLS_CERT=/run/infrascope/tls/server.crt
REMOTE_TLS_KEY=/run/infrascope/tls/server.key
REMOTE_WORKSPACE=default
REMOTE_GATEWAY_ID=offline-gateway-1
REMOTE_ALLOWED_CIDRS=
REMOTE_SECRET_KEYS='{"key-1":"$encryption_key"}'
REMOTE_ACTIVE_KEY_VERSION=key-1
DATABASE_URL=postgres://postgres:$database_password@db:5432/infrascope?sslmode=disable
EOF
  cat > /config/deploy.env <<EOF
COMPOSE_PROJECT_NAME=$project
HTTPS_PORT=$port
BIND_ADDRESS=$bind_address
PUBLIC_HOST=$host
APP_UID=$app_uid
APP_GID=$app_gid
EOF
  printf '{"username":"admin","displayName":"InfraScope Administrator","password":"%s"}\n' "$administrator_password" > /config/admin.json
  unset database_password encryption_key administrator_password
fi
openssl x509 -in /config/tls/server.crt -checkend 86400 -noout >/dev/null
cert_public=$(openssl x509 -in /config/tls/server.crt -pubkey -noout | openssl sha256)
key_public=$(openssl pkey -in /config/tls/server.key -pubout | openssl sha256)
[ "$cert_public" = "$key_public" ] || { echo 'TLS key/certificate mismatch' >&2; exit 2; }
cp /config/tls/server.crt /config/server-ca.crt
chown "$host_uid:$host_gid" /config /config/app.env /config/postgres.env /config/deploy.env /config/admin.json /config/server-ca.crt
chmod 700 /config
chmod 600 /config/app.env /config/postgres.env /config/deploy.env /config/admin.json
chmod 644 /config/server-ca.crt
chown "$app_uid:$app_gid" /config/tls /config/tls/server.crt /config/tls/server.key /logs/app
chmod 700 /config/tls
chmod 600 /config/tls/server.key
chmod 644 /config/tls/server.crt
chmod 750 /logs/app
chown "$postgres_uid:$host_gid" /logs/postgres
chmod 2750 /logs/postgres
printf 'Configuration ready. Private administrator credentials: config/admin.json\n'

# The postgres entrypoint drops privileges and must traverse the bind root.
# Change only the mount root, preserving ownership of existing database files.
chown "$postgres_uid:$host_gid" /database
chmod 700 /database
