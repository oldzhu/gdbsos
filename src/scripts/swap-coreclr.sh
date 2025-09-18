#!/usr/bin/env bash
set -euo pipefail

# swap-coreclr.sh
# Helper to backup and swap in freshly built CoreCLR (libcoreclr.so + libmscordaccore.so + libclrjit.so) and their .dbg files
# for a specific runtime version (default 8.0.15) inside the diagnostics repo layout. Optionally also swaps
# System.Private.CoreLib.dll (+ .pdb) when SWAP_CORELIB=1 is set.
#
# Usage:
#   scripts/swap-coreclr.sh apply   # backup originals (once) and copy new debug build in
#   scripts/swap-coreclr.sh restore # restore originals from backup
#   scripts/swap-coreclr.sh status  # show which set is currently active
#
# Environment overrides:
#   RUNTIME_VERSION   (default: 8.0.15)
#   BUILD_CONFIG      (default: Debug)
#   BUILD_ARCH        (default: Linux.x64.Debug)  # matches artifacts/bin/coreclr/<arch>
#   BUILD_ROOT        (default: src/runtime/artifacts/bin/coreclr)
#   SHARED_ROOT       (default: src/diagnostics/.dotnet/shared/Microsoft.NETCore.App)
#   FILES             (default: "libcoreclr.so libmscordaccore.so libclrjit.so")
#   SWAP_CORELIB      (default: 1) if 1 also copy System.Private.CoreLib.dll (+ .pdb) from IL dir
#   CORELIB_IL_DIR    (default derived from BUILD_ROOT/BUILD_ARCH/IL) override if layout changes
#
# Backups are stored under: <SHARED_ROOT>/<RUNTIME_VERSION>/backup-coreclr-swap/
# Each file: <name>.orig
# We also copy matching .dbg files if present next to source .so.
#
# Safety:
# - Will not overwrite existing backups unless FORCE_BACKUP=1
# - Verifies source files exist before applying
# - Verifies backups exist before restore

RUNTIME_VERSION="${RUNTIME_VERSION:-8.0.15}"
BUILD_CONFIG="${BUILD_CONFIG:-Debug}"
BUILD_ARCH="${BUILD_ARCH:-linux.x64.${BUILD_CONFIG}}"
BUILD_ROOT="${BUILD_ROOT:-src/runtime/artifacts/bin/coreclr}"
SHARED_ROOT="${SHARED_ROOT:-src/diagnostics/.dotnet/shared/Microsoft.NETCore.App}"
FILES_DEFAULT="libcoreclr.so libmscordaccore.so libclrjit.so"
FILES="${FILES:-$FILES_DEFAULT}"
FORCE_BACKUP="${FORCE_BACKUP:-0}"
SWAP_CORELIB="${SWAP_CORELIB:-1}"

CORELIB_IL_DIR="${CORELIB_IL_DIR:-}" # allow override before computing source_dir dependent default

# Resolve repository root robustly. Prefer git, fallback to parent of parent of this script (since we're under src/scripts).
if command -v git >/dev/null 2>&1; then
  repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
fi
if [[ -z "${repo_root:-}" ]]; then
  _SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  repo_root="$(cd "${_SCRIPT_DIR}/../.." && pwd)"
fi
source_dir="$repo_root/$BUILD_ROOT/$BUILD_ARCH"
if [ -z "$CORELIB_IL_DIR" ]; then
  CORELIB_IL_DIR="$source_dir/IL"
fi
shared_version_dir="$repo_root/$SHARED_ROOT/$RUNTIME_VERSION"
backup_dir="$shared_version_dir/backup-coreclr-swap"

color() { local c="$1"; shift; printf "\033[%sm%s\033[0m" "$c" "$*"; }
info(){ echo "$(color 36 [info]) $*"; }
warn(){ echo "$(color 33 [warn]) $*"; }
err(){ echo "$(color 31 [err]) $*" >&2; }

need() { command -v "$1" >/dev/null 2>&1 || { err "Required tool '$1' not found"; exit 1; }; }
need stat

usage(){ sed -n '1,/^exit_usage_marker$/p' "$0" | sed '$d'; exit 1; }

[ $# -ge 1 ] || usage
cmd="$1"; shift || true

status(){
  echo "Runtime version      : $RUNTIME_VERSION"
  echo "Source build dir     : $source_dir"
  echo "Shared version dir   : $shared_version_dir"
  echo "Backup dir           : $backup_dir"
  echo "Swap CoreLib         : $SWAP_CORELIB"
  if [ "$SWAP_CORELIB" = "1" ]; then
    echo "CoreLib IL dir       : $CORELIB_IL_DIR"
  fi
  for f in $FILES; do
    local shared_f="$shared_version_dir/$f"
    local backup_f="$backup_dir/$f.orig"
    if [ -f "$backup_f" ]; then
      if cmp -s "$shared_f" "$backup_f"; then
        echo " - $f: ORIGINAL (matches backup)"
      else
        echo " - $f: SWAPPED (differs from backup)"
      fi
    else
      echo " - $f: (no backup) current in place"
    fi
  done
}

ensure_sources(){
  for f in $FILES; do
    if [ ! -f "$source_dir/$f" ]; then
      err "Source $source_dir/$f not found. Build first."
      exit 1
    fi
  done
}

apply_swap(){
  ensure_sources
  mkdir -p "$backup_dir"
  for f in $FILES; do
    local shared_f="$shared_version_dir/$f"
    local backup_f="$backup_dir/$f.orig"
    if [ ! -f "$shared_f" ]; then
      err "Shared file $shared_f missing; aborting to avoid partial state."; exit 1; fi
    if [ -f "$backup_f" ] && [ "$FORCE_BACKUP" != "1" ]; then
      warn "Backup exists for $f (skipping backup). Use FORCE_BACKUP=1 to overwrite."
    else
      cp -p "$shared_f" "$backup_f"
      info "Backed up $f -> $backup_f"
    fi
    cp -p "$source_dir/$f" "$shared_f"
    info "Updated $shared_f -> new build"
    # Copy .dbg if present in either location
    for ext in .dbg; do
      local src_dbg="$source_dir/$f$ext"
      local shared_dbg="$shared_version_dir/$f$ext"
      local backup_dbg="$backup_dir/$f$ext.orig"
      if [ -f "$src_dbg" ]; then
        if [ -f "$shared_dbg" ] && [ ! -f "$backup_dbg" ]; then
          cp -p "$shared_dbg" "$backup_dbg" && info "Backed up $f$ext"
        fi
        cp -p "$src_dbg" "$shared_dbg" && info "Updated $shared_dbg"
      fi
    done
  done
  info "Swap complete. Run 'scripts/swap-coreclr.sh status' to verify."
  if [ "$SWAP_CORELIB" = "1" ]; then
    swap_corelib
  fi
}

restore_swap(){
  if [ ! -d "$backup_dir" ]; then
    err "No backup dir $backup_dir"; exit 1; fi
  for f in $FILES; do
    local shared_f="$shared_version_dir/$f"
    local backup_f="$backup_dir/$f.orig"
    if [ -f "$backup_f" ]; then
      cp -p "$backup_f" "$shared_f"
      info "Restored $f"
    else
      warn "No backup for $f (skipping)"
    fi
    for ext in .dbg; do
      local shared_dbg="$shared_version_dir/$f$ext"
      local backup_dbg="$backup_dir/$f$ext.orig"
      if [ -f "$backup_dbg" ]; then
        cp -p "$backup_dbg" "$shared_dbg" && info "Restored $f$ext"
      fi
    done
  done
  info "Restore complete."
  if [ "$SWAP_CORELIB" = "1" ]; then
    restore_corelib
  fi
}

swap_corelib(){
  local corelib_src="$CORELIB_IL_DIR/System.Private.CoreLib.dll"
  local corelib_pdb_src="$CORELIB_IL_DIR/System.Private.CoreLib.pdb"
  local corelib_dst="$shared_version_dir/System.Private.CoreLib.dll"
  local corelib_pdb_dst="$shared_version_dir/System.Private.CoreLib.pdb"
  local corelib_backup="$backup_dir/System.Private.CoreLib.dll.orig"
  local corelib_pdb_backup="$backup_dir/System.Private.CoreLib.pdb.orig"
  if [ ! -f "$corelib_src" ]; then
    warn "CoreLib source $corelib_src not found; skipping CoreLib swap"; return 0; fi
  if [ -f "$corelib_dst" ] && [ ! -f "$corelib_backup" ]; then
    cp -p "$corelib_dst" "$corelib_backup" && info "Backed up System.Private.CoreLib.dll"
  fi
  cp -p "$corelib_src" "$corelib_dst" && info "Updated $corelib_dst"
  if [ -f "$corelib_pdb_src" ]; then
    if [ -f "$corelib_pdb_dst" ] && [ ! -f "$corelib_pdb_backup" ]; then
      cp -p "$corelib_pdb_dst" "$corelib_pdb_backup" && info "Backed up System.Private.CoreLib.pdb"
    fi
    cp -p "$corelib_pdb_src" "$corelib_pdb_dst" && info "Updated $corelib_pdb_dst"
  fi
}

restore_corelib(){
  local corelib_dst="$shared_version_dir/System.Private.CoreLib.dll"
  local corelib_pdb_dst="$shared_version_dir/System.Private.CoreLib.pdb"
  local corelib_backup="$backup_dir/System.Private.CoreLib.dll.orig"
  local corelib_pdb_backup="$backup_dir/System.Private.CoreLib.pdb.orig"
  if [ -f "$corelib_backup" ]; then
    cp -p "$corelib_backup" "$corelib_dst" && info "Restored System.Private.CoreLib.dll"
  else
    warn "No backup for System.Private.CoreLib.dll"
  fi
  if [ -f "$corelib_pdb_backup" ]; then
    cp -p "$corelib_pdb_backup" "$corelib_pdb_dst" && info "Restored System.Private.CoreLib.pdb"
  fi
}

case "$cmd" in
  apply)   apply_swap;;
  restore) restore_swap;;
  status)  status;;
  *) usage;;
esac

exit 0

exit_usage_marker
