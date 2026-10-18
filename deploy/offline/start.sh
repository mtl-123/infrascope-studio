#!/bin/sh
set -eu
BUNDLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cd "$BUNDLE_DIR"
. "$BUNDLE_DIR/image-names.env"
host=''
port=18443
project=infrascope-offline
bind_address=0.0.0.0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --host) host=$2; shift 2;;
    --port) port=$2; shift 2;;
    --project) project=$2; shift 2;;
    --bind) bind_address=$2; shift 2;;
    *) echo 'Usage: ./start.sh --host SERVER_IP_OR_DNS [--port 18443] [--bind 0.0.0.0] [--project infrascope-offline]' >&2; exit 2;;
  esac
done
command -v docker >/dev/null || { echo 'Install Docker Engine and Compose v2 first.' >&2; exit 2; }
docker compose version >/dev/null || { echo 'Docker Compose v2 is required.' >&2; exit 2; }
case "$(uname -m)" in x86_64|amd64) :;; *) echo 'This offline package is Linux amd64 only.' >&2; exit 2;; esac
if [ "$(docker image inspect --format '{{.Id}}' "$APP_IMAGE" 2>/dev/null || true)" != "$APP_IMAGE_ID" ] ||
   [ "$(docker image inspect --format '{{.Id}}' "$PG_IMAGE" 2>/dev/null || true)" != "$PG_IMAGE_ID" ]; then
  sha256sum -c images.sha256
  docker load --input images.tar
fi
if [ -z "$host" ] && [ -s config/deploy.env ]; then
  host=$(sed -n 's/^PUBLIC_HOST=//p' config/deploy.env)
fi
[ -n "$host" ] || { echo 'First deployment: ./start.sh --host YOUR_SERVER_IP_OR_DNS' >&2; exit 2; }
for path in config config/tls data data/postgres logs logs/app logs/postgres; do
  [ ! -L "$BUNDLE_DIR/$path" ] || { echo "Refusing a symlink at $path" >&2; exit 2; }
done
umask 077
mkdir -p config data/postgres logs/app logs/postgres
postgres_uid=$(docker run --rm --pull never --network none --entrypoint id "$PG_IMAGE" -u postgres)
docker run --rm --pull never --network none --user 0:0 --entrypoint /bin/sh \
  --mount "type=bind,source=$BUNDLE_DIR/config,target=/config" \
  --mount "type=bind,source=$BUNDLE_DIR/logs,target=/logs" \
  "$APP_IMAGE" /app/offline/initialize.sh "$host" "$port" "$(id -u)" "$(id -g)" "$postgres_uid" "$project" "$bind_address"
# Docker Compose auto-loads the public deployment settings; all actual configuration remains in config/.
if [ -e .env ] || [ -L .env ]; then
  [ -L .env ] && [ "$(readlink .env)" = config/deploy.env ] || { echo 'Existing .env is not this package deployment link; preserve and review it.' >&2; exit 2; }
else
  ln -s config/deploy.env .env
fi
dc() { docker compose --project-directory "$BUNDLE_DIR" --env-file "$BUNDLE_DIR/config/deploy.env" -f "$BUNDLE_DIR/docker-compose.yml" "$@"; }
dc up -d --wait --wait-timeout 150 db
dc stop app
dc run --rm --no-deps -T app migrate
users=$(dc exec -T db psql -U postgres -d infrascope -Atc 'SELECT count(*) FROM ra_users')
case "$users" in
  0) dc run --rm --no-deps -T app bootstrap < config/admin.json;;
  ''|*[!0-9]*) echo 'Cannot determine bootstrap state; stopped without resetting credentials.' >&2; exit 2;;
esac
dc up -d --wait --wait-timeout 150 app
dc ps
origin=$(sed -n 's/^REMOTE_PUBLIC_ORIGIN=//p' config/app.env)
printf '\nReady: %s/#help\nAdministrator: config/admin.json\nLogs: logs/app/service.log and logs/postgres/\n' "$origin"
