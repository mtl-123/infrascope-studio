#!/usr/bin/env bash
_infra_rust_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# Use the optional existing checkout-local toolchain only when it is installed.
# A fresh clone uses the developer's normal rustup/cargo installation.
if [ -x "$_infra_rust_root/.dev-tools/rust/cargo/bin/cargo" ]; then
  export CARGO_HOME="$_infra_rust_root/.dev-tools/rust/cargo"
  export RUSTUP_HOME="$_infra_rust_root/.dev-tools/rust/rustup"
  export PATH="$CARGO_HOME/bin:$PATH"
fi
export PATH="$_infra_rust_root/.dev-tools/mingw/bin:$_infra_rust_root/.dev-tools/mingw/sysroot/usr/bin:$PATH"
if [ -x "$_infra_rust_root/.dev-tools/gcc/cc" ]; then
  export CC="$_infra_rust_root/.dev-tools/gcc/cc"
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$CC"
fi
if [ -x "$_infra_rust_root/.dev-tools/mingw/bin/x86_64-w64-mingw32-gcc" ]; then
  export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$_infra_rust_root/.dev-tools/mingw/bin/x86_64-w64-mingw32-gcc"
  export CC_x86_64_pc_windows_gnu="$CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER"
  export AR_x86_64_pc_windows_gnu="$_infra_rust_root/.dev-tools/mingw/sysroot/usr/bin/x86_64-w64-mingw32-ar"
fi
unset _infra_rust_root
