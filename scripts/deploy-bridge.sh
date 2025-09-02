#!/usr/bin/env bash
set -euo pipefail

# Copy the built libsosgdbbridge.so and Python plugin files next to diagnostics' libsos.so for testing/usage
# Usage:
#   scripts/deploy-bridge.sh [-c Debug|Release] [-a x64|arm64|arm] [-d <diagnostics bin dir>]
# Defaults: -c Release, autodetect arch, diagnostics dir from src/diagnostics/artifacts/bin/current

CONFIG=Release
ARCH=""
DIAG_DIR=""
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--configuration) CONFIG="${2:-Release}"; shift 2;;
    -a|--arch) ARCH="${2:-}"; shift 2;;
    -d|--diag-dir) DIAG_DIR="${2:-}"; shift 2;;
    -h|--help)
      echo "Usage: $0 [-c Debug|Release] [-a x64|arm64|arm] [-d <diagnostics bin dir>]"; exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

OS=linux
if [[ -z "${ARCH}" ]]; then
  case "$(uname -m)" in
    x86_64) ARCH=x64;;
    aarch64) ARCH=arm64;;
    armv7l|armhf) ARCH=arm;;
    s390x) ARCH=s390x;;
    ppc64le) ARCH=ppc64le;;
    *) ARCH="$(uname -m)";;
  esac
fi

BRIDGE_SO="${REPO_ROOT}/artifacts/bin/${OS}.${ARCH}.${CONFIG}/libsosgdbbridge.so"
BRIDGE_DBG="${REPO_ROOT}/artifacts/bin/${OS}.${ARCH}.${CONFIG}/libsosgdbbridge.so.dbg"
if [[ ! -f "${BRIDGE_SO}" ]]; then
  echo "ERROR: Bridge not found at ${BRIDGE_SO}. Build first." >&2
  exit 1
fi

if [[ -z "${DIAG_DIR}" ]]; then
  # Prefer 'current' symlink if available
  if [[ -d "${REPO_ROOT}/src/diagnostics/artifacts/bin/current" ]]; then
    DIAG_DIR="${REPO_ROOT}/src/diagnostics/artifacts/bin/current"
  else
    DIAG_DIR="${REPO_ROOT}/src/diagnostics/artifacts/bin/${OS}.${ARCH}.${CONFIG}"
  fi
fi

if [[ ! -d "${DIAG_DIR}" ]]; then
  echo "ERROR: Diagnostics bin dir not found: ${DIAG_DIR}" >&2
  exit 1
fi

cp -f "${BRIDGE_SO}" "${DIAG_DIR}/"
chmod 755 "${DIAG_DIR}/libsosgdbbridge.so" || true

if [[ -f "${BRIDGE_DBG}" ]]; then
  cp -f "${BRIDGE_DBG}" "${DIAG_DIR}/"
  echo "Deployed: ${BRIDGE_DBG} -> ${DIAG_DIR}/$(basename "${BRIDGE_DBG}")"
fi

echo "Deployed: ${BRIDGE_SO} -> ${DIAG_DIR}/libsosgdbbridge.so"

# If diagnostics 'current' exists and differs, copy there as well
DIAG_CURRENT_DIR="${REPO_ROOT}/src/diagnostics/artifacts/bin/current"
if [[ -d "${DIAG_CURRENT_DIR}" ]]; then
  if command -v readlink >/dev/null 2>&1; then
    DIAG_DIR_REAL="$(readlink -f "${DIAG_DIR}" 2>/dev/null || echo "${DIAG_DIR}")"
    DIAG_CURRENT_REAL="$(readlink -f "${DIAG_CURRENT_DIR}" 2>/dev/null || echo "${DIAG_CURRENT_DIR}")"
  else
    DIAG_DIR_REAL="${DIAG_DIR}"
    DIAG_CURRENT_REAL="${DIAG_CURRENT_DIR}"
  fi

  if [[ "${DIAG_CURRENT_REAL}" != "${DIAG_DIR_REAL}" ]]; then
    cp -f "${BRIDGE_SO}" "${DIAG_CURRENT_DIR}/"
    chmod 755 "${DIAG_CURRENT_DIR}/libsosgdbbridge.so" || true
    echo "Deployed: ${BRIDGE_SO} -> ${DIAG_CURRENT_DIR}/libsosgdbbridge.so"
    if [[ -f "${BRIDGE_DBG}" ]]; then
      cp -f "${BRIDGE_DBG}" "${DIAG_CURRENT_DIR}/"
      echo "Deployed: ${BRIDGE_DBG} -> ${DIAG_CURRENT_DIR}/$(basename "${BRIDGE_DBG}")"
    fi
  fi
fi

# Also copy Python plugin .py files next to the binaries to simplify loading
PY_SRC_DIR="${REPO_ROOT}/src/gdbplugin/sos"
if [[ -d "${PY_SRC_DIR}" ]]; then
  shopt -s nullglob
  PY_FILES=("${PY_SRC_DIR}"/*.py)
  if (( ${#PY_FILES[@]} > 0 )); then
    cp -f "${PY_FILES[@]}" "${DIAG_DIR}/"
    echo "Deployed Python files: ${#PY_FILES[@]} -> ${DIAG_DIR}"
    if [[ -d "${DIAG_CURRENT_DIR}" && "${DIAG_CURRENT_REAL}" != "${DIAG_DIR_REAL}" ]]; then
      cp -f "${PY_FILES[@]}" "${DIAG_CURRENT_DIR}/"
      echo "Deployed Python files to current: ${#PY_FILES[@]} -> ${DIAG_CURRENT_DIR}"
    fi
  fi
  shopt -u nullglob
fi
