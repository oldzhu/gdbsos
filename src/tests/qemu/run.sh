#!/usr/bin/env bash
# Launch an ARM64 Ubuntu cloud image under QEMU with 9p mount of the repo.
# Usage: ./run.sh /path/to/jammy-server-cloudimg-arm64.img [seed.iso]
# Optional ENV:
#   SMP=4 MEM=4096 \
#   BIOS=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
#   CODE=/usr/share/AAVMF/AAVMF_CODE.fd \
#   VARS_TEMPLATE=/usr/share/AAVMF/AAVMF_VARS.fd \
#   VARS=AAVMF_VARS.my.fd \
#   HOST_REPO=/workspaces/gdbsos \
#   SSH_PORT=2222

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${1:-}"
SEED="${2:-${SCRIPT_DIR}/seed.iso}"

if [[ -z "$IMG" ]]; then
  echo "Usage: $0 /path/to/jammy-server-cloudimg-arm64.img [seed.iso]" >&2
  exit 1
fi

SMP="${SMP:-4}"
MEM="${MEM:-4096}"
SSH_PORT="${SSH_PORT:-2222}"
# Default to the repo path on your WSL2 host (commonly ~/gdbsos). Override via HOST_REPO env.
HOST_REPO="${HOST_REPO:-${HOME}/gdbsos}"

# Try firmware paths
BIOS="${BIOS:-}"
CODE="${CODE:-}"
VARS_TEMPLATE="${VARS_TEMPLATE:-}"
VARS="${VARS:-${SCRIPT_DIR}/AAVMF_VARS.my.fd}"

if [[ -z "$BIOS" && -z "$CODE" ]]; then
  # Prefer single BIOS if present
  if [[ -f "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd" ]]; then
    BIOS="/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"
  elif [[ -f "/usr/share/AAVMF/AAVMF_CODE.fd" ]]; then
    CODE="/usr/share/AAVMF/AAVMF_CODE.fd"
    VARS_TEMPLATE="${VARS_TEMPLATE:-/usr/share/AAVMF/AAVMF_VARS.fd}"
  else
    echo "error: firmware not found. Set BIOS or CODE/VARS_TEMPLATE env vars." >&2
    exit 1
  fi
fi

# Prepare VARS for split AAVMF if needed
if [[ -n "$CODE" ]]; then
  if [[ -z "$VARS_TEMPLATE" || ! -f "$VARS_TEMPLATE" ]]; then
    echo "error: AAVMF vars template not found; set VARS_TEMPLATE (e.g., /usr/share/AAVMF/AAVMF_VARS.fd)" >&2
    exit 1
  fi
  if [[ ! -f "$VARS" ]]; then
    cp "$VARS_TEMPLATE" "$VARS"
  fi
fi

# Build QEMU cmd
CMD=(qemu-system-aarch64 -M virt -cpu cortex-a72 -smp "$SMP" -m "$MEM")
if [[ -n "$BIOS" ]]; then
  CMD+=( -bios "$BIOS" )
else
  CMD+=( -drive if=pflash,format=raw,readonly=on,file="$CODE" )
  CMD+=( -drive if=pflash,format=raw,file="$VARS" )
fi
CMD+=( -drive if=virtio,format=qcow2,file="$IMG" )
if [[ -f "$SEED" ]]; then
  CMD+=( -cdrom "$SEED" )
else
  echo "warning: seed ISO not found at $SEED; continuing without cloud-init seed" >&2
fi
CMD+=( -nic user,hostfwd=tcp::"$SSH_PORT"-:22 )
CMD+=( -virtfs local,path="$HOST_REPO",security_model=passthrough,mount_tag=host )
CMD+=( -nographic )

# Print and exec
printf 'Launching:\n%s\n' "${CMD[*]}"
exec "${CMD[@]}"
