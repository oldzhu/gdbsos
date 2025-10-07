#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"

# Sync submodules to ensure diagnostics is sync with upstream main
cd ${REPO_ROOT}/src/diagnostics
LOCAL_COMMIT=$(git rev-parse HEAD)
UPSTREAM_COMMIT=$(git ls-remote origin main | cut -f1)
if [ "$LOCAL_COMMIT" != "$UPSTREAM_COMMIT" ]; then
  echo "Upstream changes detected. Syncing..."
  rm -f ${REPO_ROOT}/.git/modules/src/diagnostics/index.lock
  git fetch origin main
  git merge origin/main
  cd ${REPO_ROOT}
  git add src/diagnostics
  git commit -m "Update submodule to latest main ($UPSTREAM_COMMIT)"
elif [ "$LOCAL_COMMIT" == "$UPSTREAM_COMMIT" ]; then
  echo "No changes detected."
  cd ${REPO_ROOT}
fi

# Compute arch/config and create stable "current" symlinks for artifacts
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
export SOS_ROOT="${DIAGNOSTICS_ROOT}/artifacts/bin/current"

# Ensure JIT memory protections are compatible with bpmd/JIT breakpoints under test.
export DOTNET_EnableWriteXorExecute=0

echo "post-start: DIAGNOSTICS_ROOT=${DIAGNOSTICS_ROOT}"
echo "post-start: DOTNET_ROOT is intentionally unset here (build.sh sets per-submodule toolsets)"
