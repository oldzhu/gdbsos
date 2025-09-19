# FAQ and Troubleshooting

## Breakpoints fail to set (W^X)

Symptoms when trying to set a breakpoint in JITted/native code:

- LLDB:

  warning: failed to set breakpoint site at 0x7fff78d43e20 for breakpoint 1.1: error: 9 sending the breakpoint request

- GDB:

  Warning:
  Cannot insert breakpoint 4.
  Cannot access memory at address 0x7fff7841d470

Cause: Write-Xor-Execute (W^X) policy for JIT code can prevent the debugger from patching an INT3 into executable pages in some environments.

Workaround: Disable W^X for the .NET runtime before starting the debugger.

```bash
export DOTNET_EnableWriteXorExecute=0
# then start your debugger
lldb -- yourapp   # or
gdb --args yourapp
```

Notes:
- This environment variable must be set in the shell before launching lldb/gdb (and the target).
- Re-enable later with `export DOTNET_EnableWriteXorExecute=1` if desired.

## Hosting initialization errors

- 0x80070057 (E_INVALIDARG) from coreclr_initialize
  - Commonly caused by relative paths in APP_PATHS/NATIVE_DLL_SEARCH_DIRECTORIES when the plugin is sourced via a relative path.
  - Fix: use an absolute path to the plugin directory. Current `sos.py` resolves its own path to absolute automatically; if issues persist, source with an absolute path:
    - `source /absolute/path/to/src/diagnostics/artifacts/bin/current/sos.py`

- 0x80131022 (HOST_E_INVALIDOPERATION)
  - Happens when hosting was already initialized in the same GDB process due to a prior attempt.
  - Fix: start a fresh GDB session and retry.

## Picking a runtime

- Prefer a stable shared runtime directory under DOTNET_ROOT:
  - `/.../.dotnet/shared/Microsoft.NETCore.App/8.0.x`
- Initialize explicitly if needed:
  - `sethostruntime -major 8 /.../Microsoft.NETCore.App/8.0.x`

## Symbols and DAC

- If `clrstack` reports DAC load issues, enable symbol servers or specify the path:
  - `setsymbolserver -ms`
  - `setclrpath <directory with libmscordaccore.so>`

## Building a Debug CoreCLR + System.Private.CoreLib for Deep Native Debugging

When you need to step inside the runtime (exception dispatch, JIT helpers, PAL, metadata loader) you want: 
1. A Debug/Checked build of the CoreCLR native runtime (libcoreclr / DAC / JIT). 
2. A matching implementation `System.Private.CoreLib.dll` (NOT the reference assembly). 
3. A reversible way to use them in the shared framework or to run them in isolation.

### Option A: Minimal Native Runtime Only

Classic path (native pieces, no CoreLib rebuild):
```bash
cd src/runtime
./src/coreclr/build-runtime.sh -c Debug
```
Artifacts land under:
```
src/runtime/artifacts/bin/coreclr/linux.x64.Debug/
  libcoreclr.so
  libmscordaccore.so          (DAC)
  libclrjit.so
  libdbgshim.so
  libsos.so / libsosplugin.so
  corerun
  *.dbg (separate debug symbols, if emitted)
```
Use `-c Checked` for extra asserts with somewhat better perf than full Debug.

### Option B: Minimal Native + CoreLib (Recommended)

Use the helper script we added for a tight inner-loop (builds `clr.runtime` then `clr.corelib`):
```bash
scripts/build-coreclr-corelib.sh             # Debug x64 by default
CONFIG=Checked scripts/build-coreclr-corelib.sh
ARCH=arm64 CONFIG=Debug scripts/build-coreclr-corelib.sh
```
You can build only one step if you just edited managed CoreLib code:
```bash
STEP=corelib scripts/build-coreclr-corelib.sh
```
Implementation CoreLib output (the one you can execute) lives at:
```
src/runtime/artifacts/bin/coreclr/linux.x64.Debug/IL/System.Private.CoreLib.dll
src/runtime/artifacts/bin/coreclr/linux.x64.Debug/IL/System.Private.CoreLib.pdb (if generated)
```
Reference assembly (DO NOT copy into runtime):
```
src/runtime/artifacts/bin/System.Private.CoreLib/ref/Debug/net8.0/System.Private.CoreLib.dll
```
Heuristics: reference is small (few hundred KB), implementation is >1MB and resides under the `IL/` directory.

### Running Without Swapping (Preferred for Isolation)
```bash
CORE_ROOT=src/runtime/artifacts/bin/coreclr/linux.x64.Debug/IL \
gdb --args $CORE_ROOT/corerun /path/to/YourApp.dll
```
Advantages: leaves the shared framework pristine, avoids accidental version bleed.

### Swapping Into the Shared Framework (8.0.15 Default)

The enhanced script `scripts/swap-coreclr.sh` now supports:
- Native libs: `libcoreclr.so`, `libmscordaccore.so`, `libclrjit.so` (+ their `.dbg`).
- Optional CoreLib swap: `System.Private.CoreLib.dll` (+ `.pdb`) when `SWAP_CORELIB=1`.

Default assumptions:
```
Shared runtime: src/diagnostics/.dotnet/shared/Microsoft.NETCore.App/<VERSION>/
Build outputs : src/runtime/artifacts/bin/coreclr/linux.x64.Debug/
Version       : 8.0.15 (override with RUNTIME_VERSION=...)
```

#### Swap Commands
Swap only native components:
```bash
scripts/swap-coreclr.sh apply
```
Swap native + CoreLib:
```bash
SWAP_CORELIB=1 scripts/swap-coreclr.sh apply
```
Check status:
```bash
scripts/swap-coreclr.sh status
```
Restore originals (native only or native+CoreLib depending on what was swapped):
```bash
SWAP_CORELIB=1 scripts/swap-coreclr.sh restore
```

#### Important Environment Overrides
```bash
RUNTIME_VERSION=8.0.15 BUILD_CONFIG=Debug scripts/swap-coreclr.sh apply
FILES="libcoreclr.so libmscordaccore.so libclrjit.so" scripts/swap-coreclr.sh status
SWAP_CORELIB=1 CORELIB_IL_DIR=/alternate/path/to/IL scripts/swap-coreclr.sh apply
```
`CORELIB_IL_DIR` lets you point at a non-standard layout (defaults to `<build>/IL`).

#### Backups & Safety
- Backups stored under: `<shared>/backup-coreclr-swap/`
- Each original becomes `<name>.orig` (including `System.Private.CoreLib.dll.orig` if CoreLib swapped).
- Existing backups are preserved unless `FORCE_BACKUP=1`.
- Always restore after focused debugging to prevent mixing builds.

### Verifying You Are Using Your Build
Inside GDB:
```bash
info shared | grep libcoreclr.so
```
Optional CoreLib check:
```bash
sha256sum src/runtime/artifacts/bin/coreclr/linux.x64.Debug/IL/System.Private.CoreLib.dll \
          src/diagnostics/.dotnet/shared/Microsoft.NETCore.App/8.0.15/System.Private.CoreLib.dll
```
Or size sanity:
```bash
stat -c '%n %s' src/diagnostics/.dotnet/shared/Microsoft.NETCore.App/8.0.15/System.Private.CoreLib.dll
```

### Build Troubleshooting
- CMake >= 3.20 required (recommend 3.27+). If upgrading, ensure `/usr/local/bin` precedes `/usr/bin` in `PATH`.
- Clear stale configure caches after toolchain changes: `rm -rf artifacts/obj/coreclr/linux.x64.Debug`.
- Do not use `-Debug` (incorrect); use `-c Debug` or `-c Checked`.
- If CoreLib swap leads to loader error 0x80131058, you copied the reference assembly—use the `IL/` one instead.

### Restoring After a Crash
If a swapped process crashes, just:
```bash
SWAP_CORELIB=1 scripts/swap-coreclr.sh restore
```
Then start a fresh debugging session.

---

For GC stress, tiering experiments, or multi-arch scenarios, extend the build script (e.g. add `-arch arm64`) before swapping. This section intentionally focuses on the minimal path for exception / JIT notification investigations.

## Long output and paging (e.g., `clru`)

- GDB’s pager captures large outputs.
  - Disable paging: `set pagination off`.
  - Capture to file: `set logging on` then run the command.
- Pressing `q` during paging may not cancel native printing from SOS; Ctrl-C interrupts GDB.
