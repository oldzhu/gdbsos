# SOS GDB Test Harness

Lightweight GDB scenario tests for the SOS GDB Python plugin.

## Plugin Discovery (Updated)
`sos.py` moved out of the diagnostics submodule; the harness now auto-detects it in published artifact folders.

When `PLUGIN_PATH` is not set, `test.sh` searches in order:
1. `artifacts/bin/linux.x64.$CONFIG/sos.py` (with `CONFIG` env var; default `Debug`)
2. `artifacts/bin/linux.x64.Debug/sos.py`
3. `artifacts/bin/linux.x64.Release/sos.py`

If none found, the script exits with an error instructing you to set `PLUGIN_PATH` explicitly.

## Files
| File | Purpose |
|------|---------|
| `test.sh` | Shell front-end: resolves plugin path, invokes harness. |
| `test_gdbsos.py` | Discovers scenarios, launches GDB per scenario, aggregates results. |
| `gdbtestutils.py` | Assertions and helper functions executed inside GDB Python. |
| `scenarios/` | Scenario modules (`t_cmd_*.py`) exercising specific SOS commands. |
| `logs/` | Generated runtime logs and summary file. |

## Key Environment Variables
| Var | Description | Default |
|-----|-------------|---------|
| `CONFIG` | Build configuration (`Debug` or `Release`). | `Debug` |
| `PLUGIN_PATH` | Explicit `sos.py` path (skip auto-detect). | (auto) |
| `ASSEMBLY` | Managed test debuggee DLL (must load CoreCLR). | (required) |
| `GDB_BIN` | GDB executable. | `gdb` |
| `HOST_BIN` | .NET host (e.g. `dotnet`). | `which dotnet` |
| `REGEX` | Scenario filename regex. | `t_cmd_.*\\.py` |
| `TIMEOUT` | Per-scenario timeout (seconds). | `120` |
| `REPEAT` | Number of passes over scenarios. | `1` |

## Typical Runs
```bash
# Debug build (auto-detects artifacts/bin/linux.x64.Debug/sos.py)
CONFIG=Debug \
ASSEMBLY=src/diagnostics/artifacts/bin/SimpleThrow/Debug/net10.0/SimpleThrow.dll \
bash src/tests/gdb/test.sh

# Release build
CONFIG=Release \
ASSEMBLY=src/diagnostics/artifacts/bin/SimpleThrow/Release/net10.0/SimpleThrow.dll \
bash src/tests/gdb/test.sh

# Explicit override
PLUGIN_PATH=artifacts/bin/linux.x64.Debug/sos.py \
ASSEMBLY=src/diagnostics/artifacts/bin/SimpleThrow/Debug/net10.0/SimpleThrow.dll \
bash src/tests/gdb/test.sh
```

## Scenario Flow
Each scenario:
1. Starts GDB in batch mode.
2. Sources the plugin (`sos.py`).
3. Launches the managed target via the host runtime.
4. Breaks into managed code (`bpmd_and_continue`).
5. Executes SOS commands and asserts output via helpers (e.g. `expect_contains`).

## Results & Logs
* Per-scenario log: `logs/<scenario>.log`
* Aggregated summary: `logs/summary`
* Success requires removing `fail_flag` and creating `fail_flag.gdb`.

Result meanings:
* Success: ≥1 assertion passed, none failed.
* Fail: At least one assertion failed.
* Timeout: Scenario exceeded `TIMEOUT`.
* Crash: Harness did not mark completion.
* Please, report: No assertions executed; investigate scenario/harness.

## Adding a Scenario
Create `scenarios/t_cmd_newfeature.py`:
```python
from gdbtestutils import bpmd_and_continue, expect_contains

def run():
    bpmd_and_continue('MyAssembly!MyType.MyMethod')
    expect_contains('clrstack', 'MyType.MyMethod')
```

## Rationale
Centralizing plugin discovery in the publish artifacts mirrors end-user usage and avoids stale paths under the diagnostics submodule. It also ensures tests track the exact built output (co-located bridge + plugin).

---
Update this README if publish layout or discovery policy changes.
