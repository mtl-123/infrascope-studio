#!/bin/sh
set -eu
BUNDLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cd "$BUNDLE_DIR"
[ -s config/deploy.env ] || { echo 'No initialized deployment configuration.' >&2; exit 2; }
exec docker compose --project-directory "$BUNDLE_DIR" --env-file "$BUNDLE_DIR/config/deploy.env" -f "$BUNDLE_DIR/docker-compose.yml" down
