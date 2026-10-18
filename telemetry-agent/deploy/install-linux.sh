#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || $1 != --install ]]; then
  echo "Usage: sudo $0 --install host|docker|pve" >&2
  echo "Installs one binary and a disabled systemd unit. Never enrolls or starts a service." >&2
  exit 2
fi
[[ $EUID -eq 0 ]] || { echo "Installation requires an explicit sudo invocation" >&2; exit 2; }
kind=$2
case "$kind" in
  host) binary=infrascope-agent ;;
  docker) binary=infrascope-docker-collector ;;
  pve) binary=infrascope-pve-collector ;;
  *) echo "Collector kind must be host, docker, or pve" >&2; exit 2 ;;
esac
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_binary="$root/$binary"
[[ -f "$source_binary" ]] || source_binary="$root/bin/$binary"
[[ -f "$source_binary" && ! -L "$source_binary" ]] || { echo "Release binary is missing or is a symbolic link" >&2; exit 2; }
unit="/etc/systemd/system/infrascope-$kind.service"
destination="/opt/infrascope/bin/$binary"
for target in /opt/infrascope /opt/infrascope/bin /etc/infrascope "/var/lib/infrascope-$kind" "$unit" "$destination"; do
  [[ ! -L "$target" ]] || { echo "Refusing symbolic-link installation target: $target" >&2; exit 2; }
done
[[ ! -e "$unit" && ! -e "$destination" ]] || { echo "An installation already exists; refusing to overwrite it. Review upgrades manually." >&2; exit 2; }
command -v systemctl >/dev/null || { echo "systemd tools are not installed" >&2; exit 2; }
if ! id infrascope-agent >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin infrascope-agent
fi
install -d -m 0755 /opt/infrascope/bin
install -d -m 0750 -o root -g infrascope-agent /etc/infrascope
install -d -m 0700 -o infrascope-agent -g infrascope-agent "/var/lib/infrascope-$kind"
install -m 0755 "$source_binary" "$destination"
install -m 0644 "$root/deploy/infrascope-$kind.service" "$unit"
systemctl daemon-reload
echo "Installed but NOT enrolled, enabled, or started: infrascope-$kind.service"
echo "Create /etc/infrascope/$kind.toml, set absolute state_dir=/var/lib/infrascope-$kind, then enroll as infrascope-agent."
echo "Set configuration ownership root:infrascope-agent and mode 0640. See deploy/DEPLOYMENT.md."
