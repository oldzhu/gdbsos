#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

GDB_BIN=${GDB_BIN:-gdb}

# Ensure JIT memory protections are compatible with bpmd/JIT breakpoints under test.
# Mirrors manual testing instructions where users export this before invoking gdb.
export DOTNET_EnableWriteXorExecute=${DOTNET_EnableWriteXorExecute:-0}

# Allow caller to specify CONFIG (Debug/Release); default to Debug
CONFIG=${CONFIG:-Debug}

# Resolve repository root (three levels up from this script: src/tests/gdb)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../../../" && pwd)

# Detect current architecture (maps uname -m to our ARCH labels)
UNAME_M=$(uname -m)
case "${UNAME_M}" in
  x86_64)   ARCH="x64" ;;
  aarch64)  ARCH="arm64" ;;
  armv7l|armhf) ARCH="arm" ;;
  s390x)    ARCH="s390x" ;;
  ppc64le)  ARCH="ppc64le" ;;
  *)        ARCH="${UNAME_M}" ;;
esac

# Write logs under arch-specific directory (e.g., logs/x64 or logs/arm64)
LOGDIR="${SCRIPT_DIR}/logs/${ARCH}"
mkdir -p "${LOGDIR}"

# If PLUGIN_PATH not provided, attempt to auto-detect sos.py in publish folders for this arch
if [[ -z "${PLUGIN_PATH:-}" ]]; then
  CANDIDATES=(
    "${REPO_ROOT}/artifacts/bin/linux.${ARCH}.${CONFIG}/sos.py"
    "${REPO_ROOT}/artifacts/bin/linux.${ARCH}.Debug/sos.py"
    "${REPO_ROOT}/artifacts/bin/linux.${ARCH}.Release/sos.py"
  )
  for c in "${CANDIDATES[@]}"; do
    if [[ -f "$c" ]]; then
      PLUGIN_PATH="$c"
      break
    fi
  done
fi

if [[ -z "${PLUGIN_PATH:-}" ]]; then
  echo "ERROR: Unable to locate sos.py in artifacts/bin/linux.${ARCH}.[Debug|Release]. Set PLUGIN_PATH explicitly." >&2
  exit 1
fi

HOST_BIN=${HOST_BIN:-"$(command -v dotnet)"}

# Auto-detect TestDebuggee assembly if ASSEMBLY not explicitly provided.
if [[ -z "${ASSEMBLY:-}" ]]; then
  TESTDBG_CANDIDATES=(
    "${REPO_ROOT}/src/diagnostics/artifacts/bin/TestDebuggee/${CONFIG}/net8.0/TestDebuggee.dll"
    "${REPO_ROOT}/src/diagnostics/artifacts/bin/TestDebuggee/Debug/net8.0/TestDebuggee.dll"
    "${REPO_ROOT}/src/diagnostics/artifacts/bin/TestDebuggee/Release/net8.0/TestDebuggee.dll"
  )
  for a in "${TESTDBG_CANDIDATES[@]}"; do
    if [[ -f "$a" ]]; then
      ASSEMBLY="$a"
      break
    fi
  done
fi

# Default SOS_ROOT to arch-specific Release unless caller overrides
export SOS_ROOT="${SOS_ROOT:-${REPO_ROOT}/src/diagnostics/artifacts/bin/linux.${ARCH}.Release}"

ASSEMBLY=${ASSEMBLY:-"/path/to/TestDebuggee.dll"}
TIMEOUT=${TIMEOUT:-120}
REGEX=${REGEX:-'t_cmd_.*\.py'}

python3 "${SCRIPT_DIR}/test_gdbsos.py" \
  --gdb "${GDB_BIN}" \
  --plugin "${PLUGIN_PATH}" \
  --host "${HOST_BIN}" \
  --assembly "${ASSEMBLY}" \
  --logdir "${LOGDIR}" \
  --timeout "${TIMEOUT}" \
  --regex "${REGEX}"
