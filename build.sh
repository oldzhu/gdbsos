#!/usr/bin/env bash
set -euo pipefail

# gdbsos build orchestrator
# 1) Builds the diagnostics submodule
# 2) Builds and installs the gdb bridge into artifacts/bin/linux.<arch>.<Config>

CONFIG="Release"
JOBS="$(nproc)"
PASS_TO_DIAG=()
SKIP_DIAG=0
DO_PACKAGE=0
# Default: deploy bridge next to diagnostics' libsos.so unless explicitly disabled
DEPLOY_TO_DIAG=1
DEPLOY_DIR=""

print_help() {
  cat <<EOF
Usage: $0 [-c Debug|Release] [--skip-diagnostics] [--package] [--no-deploy-to-diagnostics] [--deploy-dir <path>] [-- <diagnostics build.sh args...>]
Examples:
  $0 -c Release
  $0 -c Debug -- -skipmanaged
  $0 -c Release --skip-diagnostics --package
  $0 -c Release  # deploys to diagnostics by default
  $0 -c Release --no-deploy-to-diagnostics
  $0 -c Release --deploy-dir /path/to/diagnostics/artifacts/bin/current
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--configuration)
      CONFIG="${2:-Release}"; shift 2;;
    --skip-diagnostics)
      SKIP_DIAG=1; shift;;
    --package)
      DO_PACKAGE=1; shift;;
    --deploy-to-diagnostics)
      DEPLOY_TO_DIAG=1; shift;;
    --no-deploy-to-diagnostics)
      DEPLOY_TO_DIAG=0; shift;;
    --deploy-dir)
      DEPLOY_DIR="${2:-}"; shift 2;;
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
if [[ ${SKIP_DIAG} -eq 0 ]]; then
  echo "==> Building diagnostics (-c ${CONFIG})"
  pushd "${DIAG_ROOT}" >/dev/null
  ./build.sh -c "${CONFIG}" "${PASS_TO_DIAG[@]}"
  popd >/dev/null

  # Update diagnostics 'current' symlink to the built configuration
  DIAG_BIN_ROOT="${DIAG_ROOT}/artifacts/bin"
  DIAG_CFG_DIR="${DIAG_BIN_ROOT}/${OS}.${ARCH}.${CONFIG}"
  if [[ -d "${DIAG_CFG_DIR}" ]]; then
    ln -sfn "${DIAG_CFG_DIR}" "${DIAG_BIN_ROOT}/current"
    echo "==> diagnostics bin symlink: ${DIAG_BIN_ROOT}/current -> ${DIAG_CFG_DIR}"
  fi
else
  echo "==> Skipping diagnostics build as requested"
fi

# 2) Configure & build bridge
SRC_ROOT="${REPO_ROOT}/src"
if [[ ! -f "${SRC_ROOT}/CMakeLists.txt" ]]; then
  echo "ERROR: CMakeLists.txt not found at ${SRC_ROOT}" >&2
  exit 1
fi

if command -v ninja >/dev/null 2>&1; then
  GEN=( -G Ninja )
else
  GEN=( -G "Unix Makefiles" )
fi

# Prefer clang/clang++ on Unix to match diagnostics' toolchain (required for __declspec(uuid))
PREFER_CLANG_ARGS=()
if command -v clang >/dev/null 2>&1 && command -v clang++ >/dev/null 2>&1; then
  PREFER_CLANG_ARGS=( -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ )
fi

# If a cache exists with a different CXX compiler, clear the build dir to allow switching compilers
if [[ -f "${OBJ_DIR}/CMakeCache.txt" ]]; then
  if grep -q "CMAKE_CXX_COMPILER:FILEPATH=.*g\+\+" "${OBJ_DIR}/CMakeCache.txt" && command -v clang++ >/dev/null 2>&1; then
    echo "==> Detected previous GCC build cache; cleaning to switch to clang++"
    rm -rf "${OBJ_DIR}"
  fi
fi

mkdir -p "${OBJ_DIR}" "${BIN_DIR}"

# Try to locate diagnostics' libextensions.a and pass it to CMake
EXT_LIB="${DIAG_ROOT}/artifacts/obj/${OS}.${ARCH}.${CONFIG}/src/SOS/extensions/libextensions.a"
if [[ ! -f "${EXT_LIB}" ]]; then
  # Fallback: search under artifacts for the first match
  EXT_LIB_SEARCH=$(find "${DIAG_ROOT}/artifacts" -type f -name libextensions.a 2>/dev/null | head -n1 || true)
  if [[ -n "${EXT_LIB_SEARCH}" ]]; then
    EXT_LIB="${EXT_LIB_SEARCH}"
  else
    EXT_LIB=""
  fi
fi

# Fail fast if not found
if [[ -z "${EXT_LIB}" || ! -f "${EXT_LIB}" ]]; then
  echo "ERROR: Could not find diagnostics 'libextensions.a'." >&2
  echo "Searched under: ${DIAG_ROOT}/artifacts" >&2
  echo "Expected (example): ${DIAG_ROOT}/artifacts/obj/${OS}.${ARCH}.${CONFIG}/src/SOS/extensions/libextensions.a" >&2
  echo "Hint: ensure diagnostics built successfully first:" >&2
  echo "  (cd ${DIAG_ROOT} && ./build.sh -c ${CONFIG})" >&2
  exit 1
fi

echo "==> Configuring bridge (install -> ${BIN_DIR})"
# Build CMake argument list safely
CM_ARGS=(
  -S "${SRC_ROOT}"
  -B "${OBJ_DIR}"
  "${GEN[@]}"
  -DCMAKE_BUILD_TYPE="${CONFIG}"
  -DCMAKE_INSTALL_PREFIX="${BIN_DIR}"
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
  -DDIAGNOSTICS_ROOT="${DIAG_ROOT}"
  -DDIAGNOSTICS_SRC="${DIAG_ROOT}/src"
)
CM_ARGS+=( -DEXTENSIONS_LIB="${EXT_LIB}" )
# Prefer clang compilers if available
if [[ ${#PREFER_CLANG_ARGS[@]} -gt 0 ]]; then
  CM_ARGS+=( "${PREFER_CLANG_ARGS[@]}" )
fi
# Optional: also deploy the bridge into diagnostics bin
if [[ ${DEPLOY_TO_DIAG} -eq 1 ]]; then
  CM_ARGS+=( -DBRIDGE_DEPLOY_TO_DIAGNOSTICS=ON )
  if [[ -n "${DEPLOY_DIR}" ]]; then
    CM_ARGS+=( -DBRIDGE_DEPLOY_DIAG_DIR="${DEPLOY_DIR}" )
  fi
fi
cmake "${CM_ARGS[@]}"

echo "==> Building bridge"
cmake --build "${OBJ_DIR}" -- -j"${JOBS}"

echo "==> Installing bridge -> ${BIN_DIR}"
cmake --install "${OBJ_DIR}"

# Update bridge 'current' symlink to the built configuration
BRIDGE_BIN_ROOT="${REPO_ROOT}/artifacts/bin"
BRIDGE_CFG_DIR="${BRIDGE_BIN_ROOT}/${OS}.${ARCH}.${CONFIG}"
if [[ -d "${BRIDGE_CFG_DIR}" ]]; then
  ln -sfn "${BRIDGE_CFG_DIR}" "${BRIDGE_BIN_ROOT}/current"
  echo "==> bridge bin symlink: ${BRIDGE_BIN_ROOT}/current -> ${BRIDGE_CFG_DIR}"
fi

echo "==> Done"
echo "Artifacts in: ${BIN_DIR}"

# Optional packaging step: create a tar.gz bundle of the install directory
if [[ ${DO_PACKAGE} -eq 1 ]]; then
  PKG_NAME="gdbsos-linux.${ARCH}.${CONFIG}.tar.gz"
  PKG_DIR="${REPO_ROOT}/artifacts/bin"
  echo "==> Packaging ${BIN_DIR} -> ${PKG_DIR}/${PKG_NAME}"
  tar -C "${BIN_DIR}" -czf "${PKG_DIR}/${PKG_NAME}" .
  echo "==> Package created: ${PKG_DIR}/${PKG_NAME}"
fi
