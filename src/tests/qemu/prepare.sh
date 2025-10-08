#!/usr/bin/env bash
# Prepare an ARM64 QEMU test workspace under src/tests/qemu/testspaces
# - Downloads Ubuntu ARM64 cloud image
# - Copies cloud-init seeds and helpers
# - Injects your SSH public key into user-data
# - Builds seed.iso
# - Prints how to run the VM
# Usage: ./prepare.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
WORK_DIR="${SCRIPT_DIR}/testspaces"
IMG_NAME="jammy-server-cloudimg-arm64.img"
SEED_ISO="seed.iso"
DISK_SIZE="${DISK_SIZE:-20G}"

mkdir -p "$WORK_DIR"

# 1) Download cloud image if missing
IMG_PATH="$WORK_DIR/$IMG_NAME"
if [[ ! -f "$IMG_PATH" ]]; then
  echo "Downloading Ubuntu ARM64 cloud image -> $IMG_PATH" >&2
  URL="https://cloud-images.ubuntu.com/jammy/current/${IMG_NAME}"
  # Prefer curl, fallback to wget
  if command -v curl >/dev/null 2>&1; then
    curl -fL "$URL" -o "$IMG_PATH"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$IMG_PATH" "$URL"
  else
    echo "error: need curl or wget to download image" >&2
    exit 1
  fi
else
  echo "Image already exists: $IMG_PATH" >&2
fi

# 1b) Enlarge the virtual disk size to allow rootfs growth on first boot
if command -v qemu-img >/dev/null 2>&1; then
  echo "Ensuring image virtual size >= ${DISK_SIZE} (using qemu-img resize)" >&2
  # Try to detect current virtual size and skip if already larger
  CUR_VSIZE_BYTES=$(qemu-img info --output=json "$IMG_PATH" 2>/dev/null | sed -n 's/.*"virtual-size":\s*\([0-9][0-9]*\).*/\1/p' || true)
  if [[ -n "${CUR_VSIZE_BYTES}" ]]; then
    # Convert DISK_SIZE (e.g., 20G) to bytes via qemu-img (portable) by creating a temp raw size string is non-trivial; simply attempt resize which is idempotent for >= sizes
    :
  fi
  # This is safe even if already larger; qemu-img will set to requested size
  qemu-img resize "$IMG_PATH" "$DISK_SIZE"
else
  echo "warning: qemu-img not found; skipping disk resize. Install qemu-utils and re-run if you hit 'No space left on device'." >&2
fi

# 2) Copy meta-data, user-data, and helper scripts into testspaces
cp -f "$SCRIPT_DIR/meta-data" "$WORK_DIR/meta-data"
cp -f "$SCRIPT_DIR/user-data" "$WORK_DIR/user-data"
cp -f "$SCRIPT_DIR/make-seed.sh" "$WORK_DIR/make-seed.sh"
cp -f "$SCRIPT_DIR/run.sh" "$WORK_DIR/run.sh"
chmod +x "$WORK_DIR/make-seed.sh" "$WORK_DIR/run.sh"

# 3) No SSH key required: cloud-init enables password auth and empties the dev password.
echo "Configured password-based SSH (empty password for user 'dev') via cloud-init user-data." >&2

# 4) Build seed ISO in testspaces
pushd "$WORK_DIR" >/dev/null
./make-seed.sh "$WORK_DIR/$SEED_ISO"
popd >/dev/null

# 5) Print next steps
cat <<EOF

Prepared QEMU test workspace:
  Image: $IMG_PATH
  Seed : $WORK_DIR/$SEED_ISO

You can start the VM now:
  (cd "$WORK_DIR" && ./run.sh "$IMG_NAME" "$SEED_ISO")

If firmware paths differ on your host, set BIOS explicitly, e.g.:
  (cd "$WORK_DIR" && BIOS=/usr/share/edk2/aarch64/QEMU_EFI.fd ./run.sh "$IMG_NAME" "$SEED_ISO")

Inside the VM, your repo will be mounted at /workspaces
EOF
