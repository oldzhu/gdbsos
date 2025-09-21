Sync SOS Help: Refresh from LLDB
================================

This guide shows how to re-capture SOS help/aliases from the upstream LLDB plugin and regenerate the GDB help module so "help sos" and "soshelp" stay in sync.

Prereqs
- LLDB installed and on PATH (lldb --version)
- Built diagnostics repo (libsosplugin.so) and a runnable managed sample app
- This repo checked out with diagnostics submodule up to date (optional but recommended)

Defaults used by the scripts
- libsosplugin.so: $REPOROOT/src/diagnostics/artifacts/bin/linux.x64.Debug/libsosplugin.so
- managed app:     $REPOROOT/src/diagnostics/artifacts/bin/SimpleThrow/Debug/net8.0/SimpleThrow
- output dir:      src/tools/syncsoshelp/output
Where REPOROOT is either the REPOROOT env var or discovered via: git rev-parse --show-toplevel

1) Capture LLDB outputs
Run the capture script. You can omit arguments if the defaults above exist.

```bash
src/tools/syncsoshelp/lldb_capture.sh \
  </full/path/to/libsosplugin.so> \
  </full/path/to/managed/app> \
  src/tools/syncsoshelp/output
```

What it does
- Pre-run: loads plugin and captures "soshelp" (static table) and "help" lists
- Post-run: launches the managed app, sets a breakpoint on coreclr_execute_assembly, continues to it,
  prints "soshelp", and quits (no process kill)
- Builds command lists:
  - pre: output/soshelp_cmds.txt, output/help_cmds.txt
  - post: output/post_soshelp_cmds.txt (derived from post soshelp)
- Captures per-command text:
  - output/pre_soshelp/<cmd>.txt, output/pre_help/<cmd>.txt
  - output/post_soshelp/<cmd>.txt

2) Parse into a manifest

```bash
python3 src/tools/syncsoshelp/parse_and_manifest.py \
  --in src/tools/syncsoshelp/output \
  --out src/tools/syncsoshelp/output/manifest.json
```

Notes
- The parser extracts only the soshelp table (pre and post) and is robust to wrapped lines
- The manifest primarily uses the pre-run soshelp table for order and one-liners

3) Adjust overrides (optional)
Edit src/tools/syncsoshelp/overrides.json to:
- Add/adjust GDB-only wrappers (memory dump aliases, modules/lm, registers/r, threads, logging, setruntime, SetSymbolServer)
- Control alias safety for top-level shortcuts (e.g., avoid taking over "d", "r")

4) Generate the GDB help module

```bash
python3 src/tools/syncsoshelp/generate_gdb_help.py \
  --manifest src/tools/syncsoshelp/output/manifest.json \
  --overrides src/tools/syncsoshelp/overrides.json \
  --out src/gdbplugin/sos/_generated_help.py
```

5) Verify in GDB
- Source/load the GDB SOS plugin and run:
  - help sos        # pre-run static list should reflect the generated block
  - soshelp         # after CLR loads, shows managed/native help as usual

6) Commit (suggested)
Commit the generated file and any tool changes. The raw capture outputs can be left uncommitted.

```bash
git add src/gdbplugin/sos/_generated_help.py \
        src/tools/syncsoshelp/*.py \
        src/tools/syncsoshelp/lldb_capture.sh \
        src/tools/syncsoshelp/overrides.json \
        src/tools/syncsoshelp/HOWTO-sync.md
git commit -m "syncsoshelp: refresh captures → manifest → _generated_help; doc how-to"
```

Troubleshooting
- Hang during post-run capture: the script sets a breakpoint on coreclr_execute_assembly and continues. If your runtime path differs, adjust the breakpoint (e.g., a broader regex) in lldb_capture.sh.
- Managed app not found/executable: pass an explicit path; ensure it has execute permission (chmod +x).
- Missing libsosplugin.so: ensure diagnostics repo is built (Debug or Release) and pass its full path.
- Empty outputs: verify LLDB is present and plugins load (see pre_lldb.log / post_lldb.log for errors).
