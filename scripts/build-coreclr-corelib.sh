#!/usr/bin/env bash
set -euo pipefail
# build-coreclr-corelib.sh
# Minimal helper to build only CoreCLR native runtime + System.Private.CoreLib implementation (no full libs)
# Defaults: Debug, x64, current repo commit (assumed to match target shared framework version).
# It will:
#   1. Run ./build.sh -subset clr.runtime to build native pieces
#   2. Run ./build.sh -subset clr.corelib to build System.Private.CoreLib
#   3. Print the paths of produced artifacts (libcoreclr.so, libmscordaccore.so, libclrjit.so, System.Private.CoreLib.dll/pdb)
#
# Environment overrides / flags:
#   CONFIG=Debug (or Release)
#   ARCH=x64 (other archs supported by runtime)
#   KEEP_GOOD_ENVS=1  -> Skip clearing DOTNET_* vars (by default we unset to avoid host pollution)
#   VERBOSE=1         -> echo commands
#   STEP=runtime|corelib -> build only one step
#
# Usage:
#   scripts/build-coreclr-corelib.sh
#   CONFIG=Release scripts/build-coreclr-corelib.sh
#   STEP=corelib scripts/build-coreclr-corelib.sh (assumes runtime already built)
#
# After success you can run corerun:
#   CORE_ROOT=src/runtime/artifacts/bin/coreclr/linux.${ARCH}.${CONFIG}/IL \
#     $CORE_ROOT/corerun SomeApp.dll
#
CONFIG="${CONFIG:-Debug}"
ARCH="${ARCH:-x64}"
STEP="${STEP:-all}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT/src/runtime"

if [ "${KEEP_GOOD_ENVS:-0}" != "1" ]; then
  # Avoid leaking outer host resolution state
  unset DOTNET_ROOT DOTNET_ROOT_x64 DOTNET_MULTILEVEL_LOOKUP || true
fi

run(){ echo "[build] $*"; "$@"; }

if [ "${VERBOSE:-0}" = "1" ]; then
  set -x
fi

if [ "$STEP" = "all" ] || [ "$STEP" = "runtime" ]; then
  run ./build.sh -c "$CONFIG" -arch "$ARCH" -subset clr.runtime
fi

if [ "$STEP" = "all" ] || [ "$STEP" = "corelib" ]; then
  run ./build.sh -c "$CONFIG" -arch "$ARCH" -subset clr.corelib
fi

BIN_ROOT="${REPO_ROOT}/src/runtime/artifacts/bin/coreclr/linux.${ARCH}.${CONFIG}"
IL_DIR="$BIN_ROOT/IL"

cat <<EOF

Artifacts:
  Native libs dir: $BIN_ROOT
    - $(ls -1 $BIN_ROOT | grep -E 'lib(coreclr|mscordaccore|clrjit)\.so' || true)
  CoreLib (IL):
    $IL_DIR/System.Private.CoreLib.dll
    $IL_DIR/System.Private.CoreLib.pdb (if present)

Copy/swap helper example:
  FILES="libcoreclr.so libmscordaccore.so libclrjit.so" \
    scripts/swap-coreclr.sh apply

To also swap CoreLib run (after enhancing swap script):
  SWAP_CORELIB=1 scripts/swap-coreclr.sh apply
EOF
