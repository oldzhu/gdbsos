#!/usr/bin/env bash
set -euo pipefail

# lldb_capture.sh
# Capture LLDB SOS help outputs in batch mode.
# Usage: lldb_capture.sh [<path-to-libsosplugin.so>] [<managed-app>] [<out-dir>]
# Defaults:
#   - libsosplugin.so: $REPOROOT/src/diagnostics/artifacts/bin/linux.x64.Debug/libsosplugin.so
#   - managed-app:     $REPOROOT/src/diagnostics/artifacts/bin/SimpleThrow/Debug/net8.0/SimpleThrow
#   - out-dir:         <folder-of-this-script>/output
# Where REPOROOT is taken from env if set, or auto-detected via `git rev-parse --show-toplevel`.

# Resolve script and repo roots
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Prefer REPOROOT from environment; otherwise use git to detect top-level
REPO_ROOT="${REPOROOT:-}"
if [[ -z "$REPO_ROOT" ]]; then
	if git rev-parse --show-toplevel >/dev/null 2>&1; then
		REPO_ROOT="$(git rev-parse --show-toplevel)"
	fi
fi

# Defaults
if [[ -n "$REPO_ROOT" ]]; then
	DEF_PLUGIN="$REPO_ROOT/src/diagnostics/artifacts/bin/linux.x64.Debug/libsosplugin.so"
	DEF_APP="$REPO_ROOT/src/diagnostics/artifacts/bin/SimpleThrow/Debug/net8.0/SimpleThrow"
else
	DEF_PLUGIN=""
	DEF_APP=""
fi
DEF_OUTDIR="$SCRIPT_DIR/output"

# Positional, optional overrides
LIBSOS_PLUGIN="${1:-$DEF_PLUGIN}"
MANAGED_APP="${2:-$DEF_APP}"
OUT_DIR="${3:-$DEF_OUTDIR}"

# Validate required inputs
if [[ -z "$LIBSOS_PLUGIN" || -z "$MANAGED_APP" ]]; then
	echo "Error: Unable to resolve defaults. Set REPOROOT or pass explicit arguments." >&2
	echo "Usage: $0 [<libsosplugin.so>] [<managed-app>] [<out-dir>]" >&2
	exit 2
fi
if [[ ! -f "$LIBSOS_PLUGIN" ]]; then
	echo "Error: libsosplugin not found: $LIBSOS_PLUGIN" >&2
	exit 2
fi
if [[ ! -x "$MANAGED_APP" && ! -f "$MANAGED_APP" ]]; then
	echo "Warning: managed app not found or not executable: $MANAGED_APP" >&2
fi

mkdir -p "$OUT_DIR"

# Pre-run capture
PRE_CMDS=$(cat <<'EOF'
settings set target.disable-aslr true
settings set auto-confirm true
plugin load __PLUGIN__
soshelp
help
# Commands discovered in soshelp will be expanded by parse step; pre-capture the top-level only.
quit
EOF
)

PRE_CMDS=${PRE_CMDS/__PLUGIN__/$LIBSOS_PLUGIN}
echo "$PRE_CMDS" >"$OUT_DIR/pre_commands.txt"

# Run LLDB in batch for pre-run
LLDB_LOG_PRE="$OUT_DIR/pre_lldb.log"
lldb -b -Q -o "plugin load $LIBSOS_PLUGIN" -o "soshelp" -o "help" -o "quit" -- 2>"$OUT_DIR/pre_stderr.txt" | tee "$LLDB_LOG_PRE" >/dev/null

# Build command lists from pre-run outputs (static soshelp block + user-defined help commands)
SOSHELP_CMDS="$OUT_DIR/soshelp_cmds.txt"
HELP_CMDS="$OUT_DIR/help_cmds.txt"
tmp_static="$OUT_DIR/.static_soshelp.txt"
tmp_udef="$OUT_DIR/.udef_help.txt"

# Extract static soshelp block lines between the soshelp call and next (lldb) prompt
awk '
	/\(lldb\) soshelp/ {capture=1; next}
	capture && /^\(lldb\) / {capture=0}
	capture {print}
' "$LLDB_LOG_PRE" >"$tmp_static" || true

### From static block, take the left column (before long spacing) and split aliases by comma; take first token per alias
STATIC_NAMES=$(sed 's/  \{2,\}.*$//' "$tmp_static" | tr -d '\r' | awk -F',' '{for(i=1;i<=NF;i++){seg=$i; gsub(/^ +| +$/, "", seg); split(seg, a, " "); if(a[1]!="") print a[1];}}')

# Extract user-defined commands from LLDB help section (robust to wrapped descriptions)
awk '
	/^Current user-defined commands:/ {ud=1; next}
	ud && /^\(lldb\) / {ud=0}
	ud {
		# Skip the trailing info line if present
		if ($0 ~ /^[[:space:]]*For more information/) next
		# Only take lines that look like: <cmd>  -- <desc>
		if ($0 ~ /^[[:space:]]*[[:alnum:]_.-]+[[:space:]]+--[[:space:]]/) {
			cmd=$1; gsub(/,/, "", cmd); print cmd
		}
	}
' "$LLDB_LOG_PRE" >"$tmp_udef" || true

# Unique into two lowercase lists
echo "$STATIC_NAMES" | tr -d '\r' | awk 'NF{print tolower($1)}' | sort -u >"$SOSHELP_CMDS"
cat "$tmp_udef" | tr -d '\r' | awk 'NF{print tolower($1)}' | sort -u >"$HELP_CMDS"

# Create folders for per-command outputs
mkdir -p "$OUT_DIR/pre_soshelp" "$OUT_DIR/post_soshelp" "$OUT_DIR/pre_help"

# Capture pre-run per-command: soshelp <cmd> for soshelp list
while IFS= read -r cmd; do
	[[ -z "$cmd" ]] && continue
	out_file="$OUT_DIR/pre_soshelp/${cmd}.txt"
	lldb -b -Q \
		-o "plugin load $LIBSOS_PLUGIN" \
		-o "soshelp $cmd" \
		-o "quit" -- >"$out_file" 2>/dev/null || true
done <"$SOSHELP_CMDS"

# Capture pre-run per-command: help <cmd> for help list
while IFS= read -r cmd; do
	[[ -z "$cmd" ]] && continue
	out_file="$OUT_DIR/pre_help/${cmd}.txt"
	lldb -b -Q \
		-o "plugin load $LIBSOS_PLUGIN" \
		-o "help $cmd" \
		-o "quit" -- >"$out_file" 2>/dev/null || true
done <"$HELP_CMDS"

# Post-run capture: launch, set breakpoint on coreclr_execute_assembly, continue to it, then soshelp; no process kill.
POST_CMDS=$(cat <<'EOF'
settings set target.disable-aslr true
settings set auto-confirm true
plugin load __PLUGIN__
target create "__APP__"
process launch --stop-at-entry
br set -r coreclr_execute_assembly
continue
soshelp
quit
EOF
)
POST_CMDS=${POST_CMDS/__PLUGIN__/$LIBSOS_PLUGIN}
POST_CMDS=${POST_CMDS/__APP__/$MANAGED_APP}
echo "$POST_CMDS" >"$OUT_DIR/post_commands.txt"

LLDB_LOG_POST="$OUT_DIR/post_lldb.log"
lldb -b -Q \
	-o "settings set target.disable-aslr true" \
	-o "settings set auto-confirm true" \
	-o "plugin load $LIBSOS_PLUGIN" \
	-o "target create \"$MANAGED_APP\"" \
	-o "process launch --stop-at-entry" \
	-o "br set -r coreclr_execute_assembly" \
	-o "continue" \
	-o "soshelp" \
	-o "quit" \
	-- 2>"$OUT_DIR/post_stderr.txt" | tee "$LLDB_LOG_POST" >/dev/null

# Build post-run soshelp command list based on the post-run soshelp output
POST_SOSHELP_CMDS="$OUT_DIR/post_soshelp_cmds.txt"
tmp_post_static="$OUT_DIR/.post_static_soshelp.txt"
awk '
	/\(lldb\) soshelp/ {capture=1; next}
	capture && /^\(lldb\) / {capture=0}
	capture {print}
' "$LLDB_LOG_POST" >"$tmp_post_static" || true

POST_STATIC_NAMES=$(sed 's/  \{2,\}.*$//' "$tmp_post_static" | tr -d '\r' | awk -F',' '{for(i=1;i<=NF;i++){seg=$i; gsub(/^ +| +$/, "", seg); split(seg, a, " "); if(a[1]!="") print a[1];}}')

echo "$POST_STATIC_NAMES" | tr -d '\r' | awk 'NF{print tolower($1)}' | sort -u >"$POST_SOSHELP_CMDS"

# Capture post-run per-command: soshelp <cmd> (launch per command, breakpoint/continue, then quit; no kill)
while IFS= read -r cmd; do
	[[ -z "$cmd" ]] && continue
	out_file="$OUT_DIR/post_soshelp/${cmd}.txt"
	lldb -b -Q \
		-o "settings set target.disable-aslr true" \
		-o "settings set auto-confirm true" \
		-o "plugin load $LIBSOS_PLUGIN" \
		-o "target create \"$MANAGED_APP\"" \
		-o "process launch --stop-at-entry" \
		-o "br set -r coreclr_execute_assembly" \
		-o "continue" \
		-o "soshelp $cmd" \
		-o "quit" -- >"$out_file" 2>/dev/null || true
done <"$POST_SOSHELP_CMDS"

echo "Captured:\n  $LLDB_LOG_PRE\n  $LLDB_LOG_POST\n  $(wc -l <"$SOSHELP_CMDS") soshelp cmds, $(wc -l <"$HELP_CMDS") help cmds; see pre_/post_ folders" >&2
