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

# [Removed] 'current' symlink (multi-arch safe):
# We no longer create or update artifacts/bin/current because it can flip between
# different arch/config combinations and cause confusion. Scripts should use explicit
# linux.<arch>.<config> paths instead (defaulting to Release). The previous code was:
#   DIAG_BIN_ROOT="${REPO_ROOT}/src/diagnostics/artifacts/bin"
#   TARGET="${DIAG_BIN_ROOT}/${CONFIG_DIR}"
#   LINK="${DIAG_BIN_ROOT}/current"
#   ln -sfn "${TARGET}" "${LINK}"

# [Removed] 'current' symlink for bridge as well; prefer explicit linux.<arch>.<config>.
# Previous code updated ${REPO_ROOT}/artifacts/bin/current to Release/Debug for this arch.

# Export minimal variables; default SOS_ROOT to arch-specific Release unless overridden.
export DIAGNOSTICS_ROOT="${REPO_ROOT}/src/diagnostics"
DIAG_BIN_ROOT="${DIAGNOSTICS_ROOT}/artifacts/bin"
export SOS_ROOT="${SOS_ROOT:-${DIAG_BIN_ROOT}/linux.${ARCH}.Release}"

# Ensure JIT memory protections are compatible with bpmd/JIT breakpoints under test.
export DOTNET_EnableWriteXorExecute=0

echo "post-start: DIAGNOSTICS_ROOT=${DIAGNOSTICS_ROOT}"
echo "post-start: DOTNET_ROOT is intentionally unset here (build.sh sets per-submodule toolsets)"
