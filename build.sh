#!/usr/bin/env bash
set -euo pipefail

# gdbsos build orchestrator
# 1) Builds the diagnostics submodule
# 2) Builds and installs the gdb bridge into artifacts/bin/linux.<arch>.<Config>
#
# NOTE (2025-09-25): Deployment to the diagnostics bin directory (next to libsos.so)
# is obsolete. The Python plugin now locates libsos via $SOS_ROOT or ~/.dotnet/sos,
# and the bridge (libsosgdbbridge.so) is expected to be co-located with the Python files.
# Any deploy-to-diagnostics options are retained for backwards compatibility but are no-ops.

CONFIG="Release"
JOBS="$(nproc)"
PASS_TO_DIAG=()
SKIP_DIAG=0
DO_PACKAGE=0
# Optional release tag version used in package filenames (e.g., v0.1.0)
TAG_VERSION=""
# Deprecated: deploy-to-diagnostics is no longer needed (see note above)
DEPLOY_TO_DIAG=0
DEPLOY_DIR=""

print_help() {
  cat <<EOF
Usage: $0 [-c Debug|Release] [--skip-diagnostics] [--package] [-- <diagnostics build.sh args...>]
Examples:
  $0 -c Release
  $0 -c Debug -- -skipmanaged
  $0 -c Release --skip-diagnostics --package
  $0 -c Release
  $0 -c Release --package --tag v0.1.0
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
    --tag)
      TAG_VERSION="${2:-}"; shift 2;;
    --deploy-to-diagnostics)
      echo "[note] --deploy-to-diagnostics is deprecated and ignored (no-op)." >&2; shift;;
    --no-deploy-to-diagnostics)
      echo "[note] --no-deploy-to-diagnostics is deprecated and ignored (no-op)." >&2; shift;;
    --deploy-dir)
      echo "[note] --deploy-dir is deprecated and ignored (no-op)." >&2; shift 2;;
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
  # Configure per-arch, per-submodule dotnet toolset location (Option B)
  export DOTNET_MULTILEVEL_LOOKUP=0
  export DOTNET_INSTALL_DIR="${DIAG_ROOT}/.dotnet.${ARCH}"
  export DOTNET_ROOT="${DOTNET_INSTALL_DIR}"
  export PATH="${DOTNET_INSTALL_DIR}:${DOTNET_INSTALL_DIR}/tools:${PATH}"

  # Ensure the required SDK version (from diagnostics/global.json) is installed
  # into DOTNET_INSTALL_DIR so Arcade's InitializeDotNetCli will honor it.
  echo "==> Diagnostics toolset:"
  echo "    ARCH=${ARCH} uname -m=$(uname -m)"
  echo "    DOTNET_INSTALL_DIR=${DOTNET_INSTALL_DIR}"
  echo "    DOTNET_ROOT=${DOTNET_ROOT}"
  if [[ ":${PATH}:" == *":${DOTNET_INSTALL_DIR}:"* ]]; then
    echo "    PATH includes DOTNET: yes"
  else
    echo "    PATH includes DOTNET: no"
  fi

  DIAG_GLOBAL_JSON="${DIAG_ROOT}/global.json"
  # Acquire a submodule-local lock to avoid races when multiple builds flip .dotnet symlink
  HAVE_DIAG_LOCK=0
  if command -v flock >/dev/null 2>&1; then
    DIAG_LOCK_FILE="${DIAG_ROOT}/.dotnet-arcade.lock"
    # shellcheck disable=SC3003
    exec {DIAG_LOCK_FD}>"${DIAG_LOCK_FILE}"
    echo "==> Acquiring diagnostics toolset lock: ${DIAG_LOCK_FILE}"
    flock "${DIAG_LOCK_FD}"
    HAVE_DIAG_LOCK=1
  fi
  # Ensure diagnostics/.dotnet resolves to the per-arch folder so Arcade fallback hits the suffixed dir
  DIAG_LINK_TARGET="${DIAG_ROOT}/.dotnet"
  DIAG_SUFFIX_DIR="${DIAG_ROOT}/.dotnet.${ARCH}"
  mkdir -p "${DIAG_SUFFIX_DIR}" || true
  ensure_diag_link() {
    local link_target="$1" suffix_dir="$2"
    if [[ -L "$link_target" ]]; then
      local dest
      dest="$(readlink -f "$link_target" || true)"
      local want
      want="$(readlink -f "$suffix_dir" || true)"
      if [[ "$dest" != "$want" ]]; then
        echo "WARN: $link_target currently points to $dest, expected $want"
        if [[ "${DIAG_DOTNET_FORCE:-0}" == "1" ]]; then
          ln -sfn "$suffix_dir" "$link_target"
        elif [[ -t 0 || -t 1 ]]; then
          read -r -p "Relink $link_target to $suffix_dir? [y/N] " ans < /dev/tty || ans=""
          if [[ "$ans" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            ln -sfn "$suffix_dir" "$link_target"
          else
            echo "Aborting: $link_target not relinked. Set DIAG_DOTNET_FORCE=1 to override." >&2
            exit 2
          fi
        else
          echo "Non-interactive session. Set DIAG_DOTNET_FORCE=1 to relink $link_target to $suffix_dir." >&2
          exit 2
        fi
      fi
    elif [[ -d "$link_target" ]]; then
      echo "WARN: $link_target exists as a directory; this can cause cross-arch mixing"
      if [[ "${DIAG_DOTNET_FORCE:-0}" == "1" ]]; then
        rm -rf "$link_target"
        ln -sfn "$suffix_dir" "$link_target"
      elif [[ -t 0 || -t 1 ]]; then
        read -r -p "Remove directory and create symlink to $suffix_dir? [y/N] " ans < /dev/tty || ans=""
        if [[ "$ans" =~ ^([yY][eE][sS]|[yY])$ ]]; then
          rm -rf "$link_target"
          ln -sfn "$suffix_dir" "$link_target"
        else
          echo "Aborting: $link_target left as directory. Set DIAG_DOTNET_FORCE=1 to override." >&2
          exit 2
        fi
      else
        echo "Non-interactive session. Set DIAG_DOTNET_FORCE=1 to replace $link_target with symlink to $suffix_dir." >&2
        exit 2
      fi
    else
      ln -sfn "$suffix_dir" "$link_target"
    fi
  }
  ensure_diag_link "$DIAG_LINK_TARGET" "$DIAG_SUFFIX_DIR"

  # Make sure submodule local excludes ignore .dotnet* so git status stays clean
  if command -v git >/dev/null 2>&1; then
    DIAG_EXCLUDE_FILE="$(git -C "${DIAG_ROOT}" rev-parse --git-path info/exclude 2>/dev/null || true)"
    if [[ -n "${DIAG_EXCLUDE_FILE}" ]]; then
      mkdir -p "$(dirname "${DIAG_EXCLUDE_FILE}")" || true
      for pat in ".dotnet*" ".dotnet.*"; do
        if [[ -f "${DIAG_EXCLUDE_FILE}" ]]; then
          grep -qxF "${pat}" "${DIAG_EXCLUDE_FILE}" || echo "${pat}" >> "${DIAG_EXCLUDE_FILE}"
        else
          echo "${pat}" >> "${DIAG_EXCLUDE_FILE}"
        fi
      done
    fi
  fi

  if [[ -f "${DIAG_GLOBAL_JSON}" ]]; then
    # Best-effort install. dotnet-install.sh is idempotent and will skip if present.
    TMPDIR_DIAG="$(mktemp -d)"
    INSTALLER_SH="${TMPDIR_DIAG}/dotnet-install.sh"
    # Prefer official installer URL; fall back to Arcade one if needed.
    if curl -sSfL "https://dot.net/v1/dotnet-install.sh" -o "${INSTALLER_SH}"; then
      :
    else
      curl -sSfL "https://builds.dotnet.microsoft.com/dotnet/scripts/v1/dotnet-install.sh" -o "${INSTALLER_SH}"
    fi
    chmod +x "${INSTALLER_SH}"

    # Map architecture for installer (x64/arm64 only; omit if unknown)
    INSTALL_ARCH=""
    case "${ARCH}" in
      x64) INSTALL_ARCH="x64" ;;
      arm64) INSTALL_ARCH="arm64" ;;
      *) INSTALL_ARCH="" ;;
    esac

    echo "==> Ensuring diagnostics SDK per global.json is present under ${DOTNET_INSTALL_DIR}"
    # Optional timeout in seconds for dotnet-install; set DOTNET_INSTALL_TIMEOUT to enable.
    INSTALL_TIMEOUT="${DOTNET_INSTALL_TIMEOUT:-0}"
    timeout_cmd=()
    if [[ "${INSTALL_TIMEOUT}" =~ ^[0-9]+$ ]] && [[ "${INSTALL_TIMEOUT}" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
      # Use --foreground to allow Ctrl-C to be handled properly in terminals
      timeout_cmd=(timeout --foreground "${INSTALL_TIMEOUT}")
      echo "    (with timeout ${INSTALL_TIMEOUT}s)"
    fi
    echo -n "    Running dotnet-install.sh"; [[ -n "${INSTALL_ARCH}" ]] && echo " (arch=${INSTALL_ARCH})" || echo
    echo "    Args: --jsonfile ${DIAG_GLOBAL_JSON} --install-dir ${DOTNET_INSTALL_DIR} --skip-non-versioned-files${INSTALL_ARCH:+ --architecture ${INSTALL_ARCH}}"
    SECONDS=0
    if [[ -n "${INSTALL_ARCH}" ]]; then
      "${timeout_cmd[@]}" "${INSTALLER_SH}" --jsonfile "${DIAG_GLOBAL_JSON}" --install-dir "${DOTNET_INSTALL_DIR}" --architecture "${INSTALL_ARCH}" --skip-non-versioned-files || true
    else
      "${timeout_cmd[@]}" "${INSTALLER_SH}" --jsonfile "${DIAG_GLOBAL_JSON}" --install-dir "${DOTNET_INSTALL_DIR}" --skip-non-versioned-files || true
    fi
    echo "    dotnet-install completed in ${SECONDS}s"
    rm -rf "${TMPDIR_DIAG}" || true
  else
    echo "WARN: ${DIAG_GLOBAL_JSON} not found; proceeding without pre-install. Arcade may fall back to .dotnet" >&2
  fi

  pushd "${DIAG_ROOT}" >/dev/null
  ./build.sh -c "${CONFIG}" "${PASS_TO_DIAG[@]}"
  popd >/dev/null

  # Release diagnostics toolset lock if held
  if [[ "${HAVE_DIAG_LOCK}" -eq 1 ]]; then
    flock -u "${DIAG_LOCK_FD}" || true
    # Close FD
    eval "exec ${DIAG_LOCK_FD}>&-" || true
  fi

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
# Ensure Diagnostics toolset is used for any managed tooling needed during bridge configuration
export DOTNET_MULTILEVEL_LOOKUP=0
export DOTNET_INSTALL_DIR="${DIAG_ROOT}/.dotnet.${ARCH}"
export DOTNET_ROOT="${DOTNET_INSTALL_DIR}"
export PATH="${DOTNET_INSTALL_DIR}:${DOTNET_INSTALL_DIR}/tools:${PATH}"
echo "==> Bridge toolset:"
echo "    DOTNET_INSTALL_DIR=${DOTNET_INSTALL_DIR}"
echo "    DOTNET_ROOT=${DOTNET_ROOT}"
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
# Deprecated: deploy-to-diagnostics (kept for reference; no-op)
# if [[ ${DEPLOY_TO_DIAG} -eq 1 ]]; then
#   CM_ARGS+=( -DBRIDGE_DEPLOY_TO_DIAGNOSTICS=ON )
#   if [[ -n "${DEPLOY_DIR}" ]]; then
#     CM_ARGS+=( -DBRIDGE_DEPLOY_DIAG_DIR="${DEPLOY_DIR}" )
#   fi
# fi
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
  # Resolve tag if not provided: try exact tag on HEAD; else timestamp
  if [[ -z "${TAG_VERSION}" ]]; then
    if git -C "${REPO_ROOT}" describe --tags --exact-match >/dev/null 2>&1; then
      TAG_VERSION="$(git -C "${REPO_ROOT}" describe --tags --exact-match)"
    else
      TAG_VERSION="local-$(date +%Y%m%d%H%M%S)"
    fi
  fi

  PKG_DIR="${REPO_ROOT}/artifacts"
  mkdir -p "${PKG_DIR}"

  PKG_BASE="gdbsos-linux-${ARCH}-${CONFIG}-${TAG_VERSION}"
  PKG_NAME="${PKG_BASE}.tar.gz"
  PKG_SYM_NAME="${PKG_BASE}.symbols.tar.gz"

  echo "==> Packaging runtime (excluding *.dbg): ${BIN_DIR} -> ${PKG_DIR}/${PKG_NAME}"
  tar -C "${BIN_DIR}" --exclude='*.dbg' -czf "${PKG_DIR}/${PKG_NAME}" .
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${PKG_DIR}" && sha256sum "${PKG_NAME}" > "${PKG_NAME}.sha256") || true
  fi
  echo "==> Runtime package: ${PKG_DIR}/${PKG_NAME}"

  # Symbols: include all *.dbg files under BIN_DIR (any depth) if present
  # Build a list of relative paths to keep directory structure if any
  SYM_LIST_FILE=""
  SYM_COUNT=0
  SYM_LIST_FILE="$(mktemp)" || SYM_LIST_FILE=""
  if [[ -n "${SYM_LIST_FILE}" ]]; then
    # Create list of relative paths
    (cd "${BIN_DIR}" && find . -type f -name "*.dbg" -print) > "${SYM_LIST_FILE}" || true
    SYM_COUNT=$(wc -l < "${SYM_LIST_FILE}" || echo 0)
  fi
  if [[ -n "${SYM_LIST_FILE}" && ${SYM_COUNT} -gt 0 ]]; then
    echo "==> Packaging symbols (*.dbg): ${PKG_DIR}/${PKG_SYM_NAME} (${SYM_COUNT} files)"
    tar -C "${BIN_DIR}" -czf "${PKG_DIR}/${PKG_SYM_NAME}" -T "${SYM_LIST_FILE}"
    rm -f "${SYM_LIST_FILE}"
    if command -v sha256sum >/dev/null 2>&1; then
      (cd "${PKG_DIR}" && sha256sum "${PKG_SYM_NAME}" > "${PKG_SYM_NAME}.sha256") || true
    fi
    echo "==> Symbols package: ${PKG_DIR}/${PKG_SYM_NAME}"
  else
    [[ -n "${SYM_LIST_FILE}" ]] && rm -f "${SYM_LIST_FILE}"
    echo "==> No symbol files (*.dbg) found; skipping symbols package"
  fi
fi
