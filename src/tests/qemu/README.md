# ARM64 VM for GDB+SOS testing (QEMU)

This guide sets up a full-system ARM64 Ubuntu VM under QEMU to test our aarch64 builds with GDB and SOS, avoiding ptrace limits of qemu-user.

## What you'll get
- Ubuntu ARM64 (cloud image)
- .NET 8 SDK for arm64
- gdb and lldb
- SSH access via host port 2222
- A 9p-mounted shared folder mapping the repo root into the VM at `/workspaces/gdbsos`

> Note: Emulation (TCG) is CPU-only and slow. For faster runs, use native arm64 or an arm64 VM on arm64 hardware.

> Recommendation: Run qemu-system-aarch64 on your host (WSL2 host, native Linux, or Windows) rather than inside the devcontainer.
> Running full-system QEMU inside the devcontainer can work but is not recommended due to missing KVM, firmware path differences,
> and potential 9p permission issues. The helper scripts assume host execution by default (e.g., sharing `~/gdbsos`).

---

## 1) Prerequisites on the host
- QEMU system packages (host x64 Linux):
  - `qemu-system-aarch64`
  - Firmware: either `/usr/share/qemu-efi-aarch64/QEMU_EFI.fd` OR the split AAVMF files:
    - Code: `/usr/share/AAVMF/AAVMF_CODE.fd`
    - Vars: `/usr/share/AAVMF/AAVMF_VARS.fd` (copy to a writable path)
- `cloud-init` tools are not strictly required; we create a seed ISO with `genisoimage` or `mkisofs`.

Optional packages: `wget`, `genisoimage` (or `mkisofs`).

Helper scripts in this folder:
- `make-seed.sh` – creates `seed.iso` from `meta-data` and `user-data`
- `run.sh` – starts QEMU; auto-detects firmware and mounts this repo via 9p

## 2) Download an Ubuntu ARM64 cloud image
- Example (Jammy 22.04):
  - https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64.img
  - Save as `jammy-server-cloudimg-arm64.img` next to this README.

## 3) Create cloud-init seed (user + packages)
This repo includes two seed files:
- `src/tests/qemu/meta-data`
- `src/tests/qemu/user-data`

Edit `user-data` to insert your SSH public key:
- Replace `CHANGE_ME_ADD_YOUR_SSH_PUBLIC_KEY` with the contents of your `~/.ssh/id_rsa.pub` (or ed25519, etc.).

Create an ISO seed image (you can use the helper or run the commands directly):

- Using the helper:

  ./make-seed.sh

- Using `genisoimage` directly:

  genisoimage -output seed.iso -volid cidata -joliet -rock src/tests/qemu/user-data src/tests/qemu/meta-data

- Using `mkisofs` directly:

  mkisofs -output seed.iso -volid cidata -joliet -rock src/tests/qemu/user-data src/tests/qemu/meta-data

This `seed.iso` should be next to the downloaded `.img` file or give QEMU the correct path.
If you need to make the helper executable: `chmod +x make-seed.sh run.sh`.

## 4) Start the VM (choose one firmware path)

- Single-file firmware (simplest) or use the helper:

  ./run.sh jammy-server-cloudimg-arm64.img seed.iso

  # or manually:

  qemu-system-aarch64 \
    -M virt -cpu cortex-a72 -smp 4 -m 4096 \
    -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    -drive if=virtio,format=qcow2,file=jammy-server-cloudimg-arm64.img \
    -cdrom seed.iso \
    -nic user,hostfwd=tcp::2222-:22 \
    -virtfs local,path=/workspaces/gdbsos,security_model=passthrough,mount_tag=host \
    -nographic

- Split AAVMF firmware (if the single-file path doesnt exist):

  cp /usr/share/AAVMF/AAVMF_VARS.fd AAVMF_VARS.my.fd

  qemu-system-aarch64 \
    -M virt -cpu cortex-a72 -smp 4 -m 4096 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.fd \
    -drive if=pflash,format=raw,file=AAVMF_VARS.my.fd \
    -drive if=virtio,format=qcow2,file=jammy-server-cloudimg-arm64.img \
    -cdrom seed.iso \
    -nic user,hostfwd=tcp::2222-:22 \
    -virtfs local,path=/workspaces/gdbsos,security_model=passthrough,mount_tag=host \
    -nographic

Notes:
- Adjust `-smp` and `-m` according to your host. CPU emulation is slow; 2 cores and 2GB also work for basic testing.
- `-virtfs` exports the host repo root at `~/gdbsos`. Inside the VM it will be mounted at `/workspaces/gdbsos` by cloud-init (via `/etc/fstab`) if available at boot. If not mounted, see the manual mount step below.
- If your firmware is installed under a different path (e.g., `/usr/share/edk2/aarch64/QEMU_EFI.fd` on some distros), set `BIOS` env var when calling `run.sh`:

  BIOS=/path/to/QEMU_EFI.fd ./run.sh jammy-server-cloudimg-arm64.img seed.iso

## 5) First boot initialization
The VM will take ~13 minutes on first boot to:
- Add Microsoft package feed
- Install .NET 8 SDK, gdb, lldb
- Create user `dev` and set up `/workspaces` mount point

SSH in when its ready:

  ssh -p 2222 dev@127.0.0.1

If the `/workspaces/gdbsos` mount is missing, mount it manually:

  sudo mkdir -p /workspaces/gdbsos
  sudo mount -t 9p host /workspaces/gdbsos -o trans=virtio,version=9p2000.L,msize=262144,cache=mmap

## 6) Verify tools
Run inside the VM:

  dotnet --info
  gdb --version
  lldb --version

## 7) Test our GDB + SOS inside the VM
- Navigate to the shared repo:

  cd /workspaces/gdbsos

- Build (inside VM) or copy your arm64 artifacts here.
- Ensure JIT memory protections are compatible with bpmd/JIT breakpoints under test
  
  export DOTNET_EnableWriteXorExecute=0

- Use GDB as usual (no ptrace limitations in full-system emulation):

  gdb --args /path/to/your/arm64/app
  (gdb) source /workspaces/gdbsos/artifacts/bin/linux.arm64.Release/sos.py
  (gdb) bpmd TestDebuggee.dll Test.DumpIL
  (gdb) run

## Troubleshooting
- Disk full / cloud-init "No space left on device":
  - The cloud image starts very small. Our `prepare.sh` will automatically grow the virtual disk with `qemu-img resize` to 20G by default. You can change this size via `DISK_SIZE`, e.g.:

    DISK_SIZE=32G ./prepare.sh

  - Cloud-init is configured to auto-grow the root partition and filesystem on first boot using `growpart` and `resize2fs`. If it didn’t expand (rare), you can run inside the VM:

    sudo growpart /dev/vda 1
    sudo resize2fs $(findmnt -n -o SOURCE /)

  - If `qemu-img` wasn’t available during prepare: install `qemu-img` (package `qemu-utils` on Debian/Ubuntu), re-run `prepare.sh`, or run `qemu-img resize jammy-server-cloudimg-arm64.img 20G` manually.
- No SSH:
  - Wait a bit longer; cloud-init may still be installing packages.
  - Ensure `hostfwd` is present and not blocked by local firewall.
- No `/workspaces`:
  - Mount manually as shown above and confirm `-virtfs` is in your QEMU command.
- .NET feed install issues:
  - Check `/var/log/cloud-init-output.log` for installation errors.
  - You can fall back to installing .NET via tarball under `/usr/share/dotnet` if apt fails.

## Cleanup / Stop
- The VM is stopped with `Ctrl+a` then `x` if youre in the nographic console.
- The disk image is your downloaded `jammy-server-cloudimg-arm64.img`; snapshot it if you want a clean reset.
