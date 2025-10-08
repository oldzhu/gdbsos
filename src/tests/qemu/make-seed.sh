#!/usr/bin/env bash
# Create a cloud-init seed ISO for the ARM64 VM.
# Usage: ./make-seed.sh [output_iso]
# - Defaults to creating seed.iso in this directory.
# Requirements: genisoimage or mkisofs

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEED_ISO="${1:-${SCRIPT_DIR}/seed.iso}"
META="${SCRIPT_DIR}/meta-data"
USER="${SCRIPT_DIR}/user-data"

if [[ ! -f "$META" || ! -f "$USER" ]]; then
  echo "error: meta-data or user-data missing in ${SCRIPT_DIR}" >&2
  exit 1
fi

# Prefer genisoimage, fallback to mkisofs
if command -v genisoimage >/dev/null 2>&1; then
  genisoimage -output "$SEED_ISO" -volid cidata -joliet -rock "$USER" "$META"
elif command -v mkisofs >/dev/null 2>&1; then
  mkisofs -output "$SEED_ISO" -volid cidata -joliet -rock "$USER" "$META"
else
  echo "error: neither genisoimage nor mkisofs is installed" >&2
  exit 1
fi

echo "Seed ISO created: $SEED_ISO"
