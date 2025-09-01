#!/usr/bin/env bash
set -euo pipefail

# gdbsos build orchestrator
# 1) Builds the diagnostics submodule
# 2) Builds and installs the gdb bridge into artifacts/bin/linux.<arch>.<Config>

CONFIG="Release"
JOBS="$(nproc)"
PASS_TO_DIAG=()

print_help() {
  cat <<EOF
Usage: $0 [-c Debug|Release] [-- <diagnostics build.sh args...>]
Examples:
  $0 -c Release
  $0 -c Debug -- -skipmanaged
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--configuration)
      CONFIG="${2:-Release}"; shift 2;;
    -h|--help)
      print_help; exit 0;;
    --)
      shift; PASS_TO_DIAG=("$@"); break;;
    *)
      echo "Unknown arg: $1" >&2; print_help; exit 2;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIAG_ROOT="${REPO_ROOT}/src/diagnostics"
DIAG_BUILD_SH="${DIAG_ROOT}/build.sh"

if [[ ! -x "${DIAG_BUILD_SH}" ]]; then
  echo "ERROR: diagnostics/build.sh not found at ${DIAG_BUILD_SH}" >&2
  echo "       Ensure the diagnostics submodule is initialized." >&2
  exit 1
fi

# Normalize platform/arch like diagnostics (linux.x64, linux.arm64, etc.)
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

BIN_DIR="${REPO_ROOT}/artifacts/bin/${OS}.${ARCH}.${CONFIG}"
OBJ_DIR="${REPO_ROOT}/artifacts/obj/gdbbridge/${OS}.${ARCH}.${CONFIG}"

# 1) Build diagnostics first
echo "==> Building diagnostics (-c ${CONFIG})"
pushd "${DIAG_ROOT}" >/dev/null
./build.sh -c "${CONFIG}" "${PASS_TO_DIAG[@]}"
popd >/dev/null

# 2) Configure & build bridge
GDBBRIDGE_SRC="${REPO_ROOT}/src/gdbplugin/bridge"
if [[ ! -f "${GDBBRIDGE_SRC}/CMakeLists.txt" ]]; then
  echo "ERROR: CMakeLists.txt not found at ${GDBBRIDGE_SRC}" >&2
  exit 1
fi

if command -v ninja >/dev/null 2>&1; then
  GEN=( -G Ninja )
else
  GEN=( -G "Unix Makefiles" )
fi

mkdir -p "${OBJ_DIR}" "${BIN_DIR}"

echo "==> Configuring bridge (install -> ${BIN_DIR})"
cmake -S "${GDBBRIDGE_SRC}" -B "${OBJ_DIR}" "${GEN[@]}" \
  -DCMAKE_BUILD_TYPE="${CONFIG}" \
  -DCMAKE_INSTALL_PREFIX="${BIN_DIR}" \
  -DDIAGNOSTICS_ROOT="${DIAG_ROOT}" \
  -DDIAGNOSTICS_SRC="${DIAG_ROOT}/src"

echo "==> Building bridge"
cmake --build "${OBJ_DIR}" -- -j"${JOBS}"

echo "==> Installing bridge -> ${BIN_DIR}"
cmake --install "${OBJ_DIR}"

echo "==> Done"
echo "Artifacts in: ${BIN_DIR}"
