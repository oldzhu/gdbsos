#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

LOGDIR="${SCRIPT_DIR}/logs"
mkdir -p "${LOGDIR}"

GDB_BIN=${GDB_BIN:-gdb}
PLUGIN_PATH=${PLUGIN_PATH:-"/workspaces/gdbsos/src/diagnostics/artifacts/bin/current/sos.py"}
HOST_BIN=${HOST_BIN:-"$(command -v dotnet)"}
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
