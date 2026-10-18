#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 host|docker|pve /absolute/config.toml [run|once|sample|status|enroll]" >&2
  exit 2
fi
kind=$1
config=$2
command=${3:-run}
case "$kind" in
  host) binary=infrascope-agent ;;
  docker) binary=infrascope-docker-collector ;;
  pve) binary=infrascope-pve-collector ;;
  *) echo "Collector kind must be host, docker, or pve" >&2; exit 2 ;;
esac
case "$command" in run|once|sample|status|enroll) ;; *) echo "Unsupported command" >&2; exit 2 ;; esac
[[ "$config" = /* && -f "$config" ]] || { echo "Use an existing absolute configuration path" >&2; exit 2; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -x "$root/$binary" ]]; then
  executable="$root/$binary"
elif [[ -x "$root/bin/$binary" ]]; then
  executable="$root/bin/$binary"
else
  echo "Binary missing: place this deployment directory beside the release binaries" >&2
  exit 2
fi
umask 077
exec "$executable" "$command" --config "$config"
