GDB SOS plugin tests
====================

This folder contains a lightweight, LLDB-inspired test harness for the GDB SOS plugin.

What it does
- Spawns GDB in batch mode per test scenario.
- Sources the deployed plugin (`src/diagnostics/artifacts/bin/current/sos.py`).
- Launches a managed debuggee via a host (e.g., `dotnet`) and an assembly (e.g., `TestDebuggee.dll`).
- Runs scenario scripts that execute SOS commands and assert on output.
- Writes a summary report and per-test logs.

Prerequisites
- GDB with Python support (the `python` command works inside GDB).
- A .NET host (e.g., `dotnet` or `corerun`) and a managed test assembly that loads CoreCLR.
- The plugin must work in your environment (symbols/runtimes discoverable).

Layout
- `test_gdbsos.py` — outer runner that spawns GDB and coordinates tests.
- `gdbtestutils.py` — utilities imported inside the GDB process (asserts, run(), helpers).
- `scenarios/` — per-command scenario modules with `runScenario(assemblyName)`.
- `logs/` — per-test stdout/stderr logs (created at runtime).

Quick start
1) Create a logs directory:
   mkdir -p tests/gdb/logs

2) Run tests by specifying the host and assembly:
   python3 tests/gdb/test_gdbsos.py \
     --gdb gdb \
   --plugin /workspaces/gdbsos/src/diagnostics/artifacts/bin/current/sos.py \
     --host "$(command -v dotnet)" \
     --assembly /path/to/TestDebuggee.dll \
     --logdir tests/gdb/logs \
     --timeout 120 \
     --regex t_cmd_

Notes
- The harness sets a pending breakpoint on `coreclr_execute_assembly` and then runs the target.
- Scenarios assume the CLR is present at that stop. Our plugin lazily initializes hosting when the CLR is loaded.
- If you don’t have `dotnet`, you can use another CoreCLR host (`corerun`) that can launch the assembly.
- If your app is single-file or self-contained, ensure it still loads `libcoreclr.so` such that SOS can attach and function.
- The `current` directory is a symlink to the platform/config folder (e.g., `linux.x64.Release`). Ensure `libsos.so` and `libsosgdbbridge.so` are present there.
