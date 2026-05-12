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

## Picking a runtime

- Prefer a stable shared runtime directory under DOTNET_ROOT:
  - `/.../.dotnet/shared/Microsoft.NETCore.App/8.0.x`
- Initialize explicitly if needed:
  - `sethostruntime -major 8 /.../Microsoft.NETCore.App/8.0.x`

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

Swap native + CoreLib:
```bash
scripts/swap-coreclr.sh apply
```
Check status:
```bash
scripts/swap-coreclr.sh status
```
Restore originals (native+CoreLib depending on what was swapped):
```bash
scripts/swap-coreclr.sh restore
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
scripts/swap-coreclr.sh restore
```
Then start a fresh debugging session.

---

For GC stress, tiering experiments, or multi-arch scenarios, extend the build script (e.g. add `-arch arm64`) before swapping. This section intentionally focuses on the minimal path for exception / JIT notification investigations.

## Long output and paging (e.g., `clru`)

- GDB’s pager captures large outputs.
  - Disable paging: `set pagination off`.
  - Capture to file: `set logging on` then run the command.
- Pressing `q` during paging may not cancel native printing from SOS; Ctrl-C interrupts GDB.

## Help and commands

- New: prefix command 'sos' with subcommands. Try:
	- help sos              # lists only SOS commands with one-line descriptions
	- help sos dumpheap     # per-command help (managed when runtime is loaded)
	- sos dumpheap -stat    # invoke an SOS subcommand
- Fallback dispatcher:
	- sos exec <cmd> [args] # runs any SOS command name dynamically (if not pre-registered)
- Top-level aliases:
	- By default, top-level commands (bpmd, clrstack, dumpheap, ...) are also registered.
	- To keep GDB's 'help data' uncluttered, disable them with:
		- export SOS_GDB_TOPLEVEL_ALIASES=0
	- The 'help' command itself is not shadowed; use 'sos help' or 'sos soshelp' for SOS help.

## Deploy options

- Obsolete: historical deploy helpers that copied the bridge and Python files into the diagnostics artifacts/bin tree have been deprecated. The build no longer deploys to diagnostics; related CMake/script logic is commented out. Rely on SOS_ROOT or ~/.dotnet/sos for libsos.so; the gdbsos automatically co-locates the bridge with libsos when needed.

## Contributing: toolsets and multi-arch builds

- This repo uses per-submodule, per-arch .NET SDK toolsets to avoid conflicts when building in multiple dev containers:
  - Diagnostics SDK: `src/diagnostics/.dotnet-x64` or `src/diagnostics/.dotnet-arm64`
  - Runtime SDK: `src/runtime/.dotnet-x64` or `src/runtime/.dotnet-arm64`
- The top-level `build.sh` sets `DOTNET_INSTALL_DIR` and `DOTNET_ROOT` (and updates `PATH`) right before invoking each submodule’s build. The devcontainer does not set a global `DOTNET_ROOT`.
- This allows you to build x64 and arm64 concurrently in separate containers without sharing the same `.dotnet` folder.

### Dev containers

- Two services exist in `.devcontainer/docker-compose.yml`: `dev-amd64` and `dev-arm64`.
- On WSL2 x86_64 hosts, `dev-arm64` uses QEMU via a one-shot `binfmt` init service that registers QEMU 10.0.14 at container start.
- Rebuild the container if you change compose or Dockerfile; no rebuild needed for script-only changes.

## CI/CD (自动化构建与测试 / Automated Build &amp; Test)

### 中文 / zh-cn

**CI 工作流** (`.github/workflows/ci.yml`) 在每次 push 和 PR 时自动运行：
- 在 `ubuntu-latest` (x64) 和 `ubuntu-24.04-arm` (arm64) 上构建 Release 版本
- 在两个架构上运行 SOS 集成测试套件
- 测试日志作为 CI 工件上传（保留 7 天）

**发布工作流** (`.github/workflows/release.yml`)：
- 在 `v*` 标签推送时触发
- 为 x64 和 arm64 构建和打包
- 上传 `.tar.gz`、`.symbols.tar.gz` 和 `.sha256` 到 GitHub Release

### English / en

**CI workflow** (`.github/workflows/ci.yml`) runs automatically on every push and PR:
- Builds Release on `ubuntu-latest` (x64) and `ubuntu-24.04-arm` (arm64)
- Runs SOS integration test suite on both architectures
- Test logs uploaded as CI artifacts (retained 7 days)

**Release workflow** (`.github/workflows/release.yml`):
- Triggers on `v*` tag push
- Builds and packages for x64 and arm64
- Uploads `.tar.gz`, `.symbols.tar.gz`, and `.sha256` to GitHub Release

## 运行测试 / Running Tests

### 本地运行 / Local Run

```bash
# x64 或 native arm64
src/tests/gdb/test.sh

# 指定配置
CONFIG=Release src/tests/gdb/test.sh

# 指定 GDB 二进制
GDB_BIN=/usr/bin/gdb src/tests/gdb/test.sh

# 仅运行特定场景
REGEX='t_cmd_clrstack' src/tests/gdb/test.sh
```

### QEMU ARM64 测试（从 x86_64） / QEMU ARM64 Testing (from x86_64)

```bash
cd src/tests/qemu
./prepare.sh
./run.sh
```

### 测试场景列表 / Test Scenario List

场景遵循 `src/tests/gdb/scenarios/t_cmd_<command>.py` 格式，包含 52 个场景（32 个基础 + 20 个新增）：

**基础命令** (32 个): bpmd (6 个变体), clrstack, clrthreads, clru, dso, dumpclass, dumpheap, dumpil, dumplog, dumpmd, dumpmodule, dumpmt, dumpobj, dumpstack, eeheap, eestack, gcroot, hist* (5), ip2md, name2ee, pe, sos, soshelp

**新增** (20 个): sosflush, sostrace, sosstatus, syncblk, threadpool, eeversion, gchandles, runtimes, clrmodules, assemblies, dumpvc, printexception, threadstate, objsize, verifyheap, dumpstackobjects, gcheapstat, finalizequeue, gcwhere, token2ee

## 设计文档 / Design Docs

架构设计文档可在 `docs/design/` 下找到（六份双语 [zh-cn + en] 文档）：
- `01-overview.md` — 系统总览与架构图
- `02-bridge-arch.md` — 原生桥接 (libsosgdbbridge.so)
- `03-plugin-services.md` — Python 服务层
- `04-managed-hosting.md` — 托管主机初始化流程
- `05-arch-detection.md` — x64/arm64 架构检测与 ABI
- `06-tracing.md` — 跟踪与诊断子系统