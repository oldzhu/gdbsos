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
# Resolve repository root robustly. Prefer git, fallback to parent of parent of this script (since we're under src/scripts).
if command -v git >/dev/null 2>&1; then
  REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
fi
if [[ -z "${REPO_ROOT:-}" ]]; then
  _SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  REPO_ROOT="$(cd "${_SCRIPT_DIR}/../.." && pwd)"
fi
cd "$REPO_ROOT/src/runtime"

if [ "${KEEP_GOOD_ENVS:-0}" != "1" ]; then
  # Avoid leaking outer host resolution state
  unset DOTNET_ROOT DOTNET_ROOT_x64 DOTNET_MULTILEVEL_LOOKUP DOTNET_INSTALL_DIR || true
fi

# Use per-arch, per-submodule dotnet toolset (Option B)
export DOTNET_MULTILEVEL_LOOKUP=0
export DOTNET_INSTALL_DIR="${REPO_ROOT}/src/runtime/.dotnet-${ARCH}"
export DOTNET_ROOT="${DOTNET_INSTALL_DIR}"
export PATH="${DOTNET_INSTALL_DIR}:${DOTNET_INSTALL_DIR}/tools:${PATH}"

# Print toolset diagnostics and ensure SDK from runtime/global.json is present
echo "==> Runtime toolset"
echo "    ARCH=${ARCH} uname -m=$(uname -m)"
echo "    DOTNET_INSTALL_DIR=${DOTNET_INSTALL_DIR}"
echo "    DOTNET_ROOT=${DOTNET_ROOT}"
if [[ ":${PATH}:" == *":${DOTNET_INSTALL_DIR}:"* ]]; then
  echo "    PATH includes DOTNET: yes"
else
  echo "    PATH includes DOTNET: no"
fi

RUNTIME_GLOBAL_JSON="${REPO_ROOT}/src/runtime/global.json"
# Ensure the runtime submodule ignores local .dotnet toolset paths in git status
if command -v git >/dev/null 2>&1; then
  RT_EXCLUDE_FILE="$(git -C "${REPO_ROOT}/src/runtime" rev-parse --git-path info/exclude 2>/dev/null || true)"
  if [[ -n "${RT_EXCLUDE_FILE}" ]]; then
    mkdir -p "$(dirname "${RT_EXCLUDE_FILE}")" || true
    for pat in ".dotnet*" ".dotnet.*"; do
      if [[ -f "${RT_EXCLUDE_FILE}" ]]; then
        grep -qxF "${pat}" "${RT_EXCLUDE_FILE}" || echo "${pat}" >> "${RT_EXCLUDE_FILE}"
      else
        echo "${pat}" >> "${RT_EXCLUDE_FILE}"
      fi
    done
  fi
fi
if [[ -f "${RUNTIME_GLOBAL_JSON}" ]]; then
  TMPDIR_RT="$(mktemp -d)"
  INSTALLER_SH="${TMPDIR_RT}/dotnet-install.sh"
  if curl -sSfL "https://dot.net/v1/dotnet-install.sh" -o "${INSTALLER_SH}"; then
    :
  else
    curl -sSfL "https://builds.dotnet.microsoft.com/dotnet/scripts/v1/dotnet-install.sh" -o "${INSTALLER_SH}"
  fi
  chmod +x "${INSTALLER_SH}"

  INSTALL_ARCH=""
  case "${ARCH}" in
    x64) INSTALL_ARCH="x64" ;;
    arm64) INSTALL_ARCH="arm64" ;;
    *) INSTALL_ARCH="" ;;
  esac

  echo "==> Ensuring runtime SDK per global.json is present under ${DOTNET_INSTALL_DIR}"
  INSTALL_TIMEOUT="${DOTNET_INSTALL_TIMEOUT:-0}"
  timeout_cmd=()
  if [[ "${INSTALL_TIMEOUT}" =~ ^[0-9]+$ ]] && [[ "${INSTALL_TIMEOUT}" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    timeout_cmd=(timeout --foreground "${INSTALL_TIMEOUT}")
    echo "    (with timeout ${INSTALL_TIMEOUT}s)"
  fi
  echo -n "    Running dotnet-install.sh"; [[ -n "${INSTALL_ARCH}" ]] && echo " (arch=${INSTALL_ARCH})" || echo
  echo "    Args: --jsonfile ${RUNTIME_GLOBAL_JSON} --install-dir ${DOTNET_INSTALL_DIR} --skip-non-versioned-files${INSTALL_ARCH:+ --architecture ${INSTALL_ARCH}}"
  SECONDS=0
  if [[ -n "${INSTALL_ARCH}" ]]; then
    "${timeout_cmd[@]}" "${INSTALLER_SH}" --jsonfile "${RUNTIME_GLOBAL_JSON}" --install-dir "${DOTNET_INSTALL_DIR}" --architecture "${INSTALL_ARCH}" --skip-non-versioned-files || true
  else
    "${timeout_cmd[@]}" "${INSTALLER_SH}" --jsonfile "${RUNTIME_GLOBAL_JSON}" --install-dir "${DOTNET_INSTALL_DIR}" --skip-non-versioned-files || true
  fi
  echo "    dotnet-install completed in ${SECONDS}s"
  rm -rf "${TMPDIR_RT}" || true
else
  echo "WARN: ${RUNTIME_GLOBAL_JSON} not found; proceeding without pre-install. Arcade may fall back to .dotnet" >&2
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
