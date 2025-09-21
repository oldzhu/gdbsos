Sync SOS Help (LLDB → GDB)
==========================

This folder contains tooling to dynamically capture SOS help/alias info from the upstream LLDB plugin and generate a manifest that the GDB plugin can consume for consistent help text and pre-run soshelp ordering.

Nothing here is wired into the build yet. Run these scripts manually when you update the diagnostics submodule or want to refresh help data.

Contents
- lldb_capture.sh: Runs LLDB in batch to capture pre-run and post-run help output.
- parse_and_manifest.py: Parses raw capture into a structured manifest.json.
- overrides.json: Local additions/overrides for GDB-only wrappers, alias safety, and ordering pins.
- generate_gdb_help.py: Produces src/gdbplugin/sos/_generated_help.py (optional import by sos.py later).

High-level flow
1) ./lldb_capture.sh <libsosplugin.so> <dotnet-host> <managed-app> <out-dir>
2) python3 parse_and_manifest.py --in <out-dir> --out manifest.json
3) Edit overrides.json as needed
4) python3 generate_gdb_help.py --manifest manifest.json --overrides overrides.json

Notes
- Step (1) can be run twice (or the script can capture both pre and post in one run). Post-run capture is reference-only; the manifest prefers pre-run one-liners and order.
- The GDB plugin should continue to work without _generated_help.py; the import will be added later with a safe fallback.
