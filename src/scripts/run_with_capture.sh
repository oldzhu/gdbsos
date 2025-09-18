#!/usr/bin/env bash
# run_with_capture.sh - convenience wrapper to start gdb with hang_capture.gdb batch
# Usage: src/scripts/run_with_capture.sh <binary> [args...]
# Example: src/scripts/run_with_capture.sh ./src/diagnostics/artifacts/bin/SimpleThrow/Debug/net8.0/SimpleThrow

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP="${SCRIPT_DIR}/hang_capture.gdb"
if [[ ! -f "$CAP" ]]; then
  echo "hang_capture.gdb not found at $CAP" >&2
  exit 1
fi
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <binary> [args...]" >&2
  exit 2
fi
exec gdb -q -x "$CAP" --args "$@"
