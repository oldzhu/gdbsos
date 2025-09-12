#!/usr/bin/env bash
set -euo pipefail

# Sync submodules to ensure diagnostics is present
if command -v git >/dev/null 2>&1; then
   if [[ $(git submodule status src/diagnostics) == -* ]]; then
      git submodule update --remote --checkout src/diagnostics
      git add src/diagnostics
      git commit -m "Update submodule to latest main ($(git -C src/diagnostics rev-parse --short HEAD))"
   fi
fi

# Compute arch/config and create stable "current" symlinks for artifacts
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
OS="linux"
UNAME_M="$(uname -m)"
case "${UNAME_M}" in
  x86_64)   ARCH="x64" ;;
  aarch64)  ARCH="arm64" ;;
  armv7l|armhf) ARCH="arm" ;;
  s390x)    ARCH="s390x" ;;
  ppc64le)  ARCH="ppc64le" ;;
  *)        ARCH="${UNAME_M}" ;;
 esac
CONFIG_DIR="linux.${ARCH}.Debug"

# Prefer Release if it exists
if [[ -d "${REPO_ROOT}/src/diagnostics/artifacts/bin/linux.${ARCH}.Release" ]]; then
  CONFIG_DIR="linux.${ARCH}.Release"
fi

# Diagnostics symlink: artifacts/bin/current -> artifacts/bin/linux.<arch>.<cfg>
DIAG_BIN_ROOT="${REPO_ROOT}/src/diagnostics/artifacts/bin"
if [[ -d "${DIAG_BIN_ROOT}" ]]; then
  TARGET="${DIAG_BIN_ROOT}/${CONFIG_DIR}"
  LINK="${DIAG_BIN_ROOT}/current"
  if [[ -d "${TARGET}" ]]; then
    ln -sfn "${TARGET}" "${LINK}"
  fi
fi

# Bridge symlink: artifacts/bin/current -> artifacts/bin/linux.<arch>.<cfg>
BRIDGE_BIN_ROOT="${REPO_ROOT}/artifacts/bin"
if [[ -d "${BRIDGE_BIN_ROOT}/linux.${ARCH}.Release" ]]; then
  ln -sfn "${BRIDGE_BIN_ROOT}/linux.${ARCH}.Release" "${BRIDGE_BIN_ROOT}/current"
elif [[ -d "${BRIDGE_BIN_ROOT}/linux.${ARCH}.Debug" ]]; then
  ln -sfn "${BRIDGE_BIN_ROOT}/linux.${ARCH}.Debug" "${BRIDGE_BIN_ROOT}/current"
fi

# Export minimal variables; sos.py will load co-located libs and .py from diagnostics/bin/current.
export DIAGNOSTICS_ROOT="${REPO_ROOT}/src/diagnostics"
export DOTNET_ROOT="${REPO_ROOT}/src/diagnostics/.dotnet"
export PATH="${DOTNET_ROOT}:${DOTNET_ROOT}/tools:${PATH}"

echo "post-start: DIAGNOSTICS_ROOT=${DIAGNOSTICS_ROOT}"
echo "post-start: DOTNET_ROOT=${DOTNET_ROOT}"
