#!/usr/bin/env bash
# Source this file; keep compiler/proxy settings local to the development shell.
_infra_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.local/go/bin:$HOME/.local/node/bin:$HOME/.cargo/bin:$PATH"
if [ -x "$_infra_root/.dev-tools/gcc/cc" ]; then
  export CC="$_infra_root/.dev-tools/gcc/cc"
  export CGO_ENABLED=1
fi
unset _infra_root
