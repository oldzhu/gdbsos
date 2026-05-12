# 01 — 系统总览 / System Overview

---

## 中文 / zh-cn

### 项目定位

gdbsos 是一个 GDB Python 扩展，用于在 GDB 调试器中承载 .NET SOS (Son of Strike) 诊断扩展。使用户能在 GDB 会话中直接运行 .NET SOS 诊断命令（如 `clrstack`、`dumpheap`、`bpmd`、`dso` 等）。

### 系统架构图

```
┌──────────────┐     GDB Python API     ┌──────────────────────┐
│              │ ◄────────────────────── │                      │
│   GDB CLI    │                         │   Python Plugin      │
│   (User)      │ ──────────────────────►│   (sos.py)           │
│              │   invoke SOS commands   │                      │
└──────────────┘                         └─────┬────────────────┘
                                               │
                         ┌─────────────────────┼─────────────────────┐
                         │                     │                     │
                    ┌────▼─────┐        ┌──────▼──────┐       ┌─────▼─────┐
                    │ services │        │   tracing   │       │    abi    │
                    │   .py    │        │    .py      │       │    .py    │
                    └────┬─────┘        └─────────────┘       └───────────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
         ┌────▼────┐ ┌───▼────┐ ┌──▼──────────┐
         │ ctypes  │ │  GDB   │ │  /proc/PID/  │
         │  FFI    │ │  API   │ │    maps      │
         └────┬────┘ └────────┘ └──────────────┘
              │
    ┌─────────┼─────────┐
    │                    │
┌───▼──────────┐  ┌──────▼──────────┐
│ libsos.so    │  │ libsosgdbbridge │
│ (SOS native) │  │    .so (C++)    │
└───┬──────────┘  └──────┬──────────┘
    │                    │
    │                    │ Extensions framework
    │                    │ IHost / IHostServices
    │                    │ Managed CLI hosting
    │                    │
    ▼                    ▼
┌─────────────────────────────────────┐
│   .NET Runtime (libcoreclr.so)      │
│   - GC, JIT, type system            │
│   - DAC (Data Access)               │
│   - Managed diagnostics             │
└─────────────────────────────────────┘
```

### 核心模块

| 模块 | 文件 | 职责 |
|------|------|------|
| 插件入口 | `sos.py` (1777 行) | libsos 加载、命令注册、bridge 共位、托管初始化、地址规范化 |
| 服务层 | `services.py` (~2190 行) | COM vtable 实现：IDebuggerServices、ILLDBServices、IHost、IHostServices、ITarget、IRuntime、ICLRDataTarget2、DAC 初始化 |
| ABI 层 | `abi.py` (342 行) | 所有 COM 接口的 vtable 结构定义、GUID/IID 常量、C 类型定义 |
| 跟踪层 | `tracing.py` (149 行) | `sostrace` 命令、分类过滤、环境变量控制 |
| 原生桥接 | `gdbbridge.cpp` (105 行) | Extensions 单例、托管初始化、命令分发、IHost* 暴露、PID 更新 |
| 构建系统 | `build.sh` (389 行) | 构建诊断子模块 + CMake 原生桥接 |

### 命令分发流程

1. 用户在 GDB 中输入命令（如 `clrstack` 或 `sos clrstack`）
2. `SOSCommand.invoke()` 被调用
3. `lazy_load_sos()` 加载 `libsos.so` 和 bridge，通过 `SOSInitializeByHost` 初始化
4. 分发前：尝试主机初始化、更新目标 PID、按需刷新
5. 尝试通过 SOS 函数指针进行原生导出分发
6. 如果原生导出未找到，尝试通过 bridge/libSOS 转发器进行托管分发
7. 使用 HRESULT 提示处理错误

### 关键设计决策

1. **Bridge 共位**：`libsosgdbbridge.so` 必须与 `libsos.so` 位于同一目录，否则托管初始化会失败（HRESULT 0x80070002）
2. **急切的托管初始化**：在 libsos 加载时尝试启动托管，以匹配 LLDB 的流程
3. **无 Python 主机回退**：如果原生主机不可用，使用 NULL 主机路径，不构造 Python 回退主机
4. **架构感知**：通过 GDB 帧架构、`show architecture` 和 `os.uname()` 支持 x64 和 arm64
5. **分类级跟踪**：通过环境变量和 `sostrace` GDB 命令在运行时控制跟踪输出

---

## English / en

### Project Positioning

gdbsos is a GDB Python extension that hosts the .NET SOS (Son of Strike) diagnostics extension within the GDB debugger. It enables users to run .NET SOS diagnostic commands (e.g., `clrstack`, `dumpheap`, `bpmd`, `dso`) directly in a GDB session.

### System Architecture (see diagram above)

### Core Modules

| Module | File(s) | Responsibility |
|--------|---------|----------------|
| Plugin Entry | `sos.py` (1777 lines) | libsos loading, command registration, bridge co-location, hosting init, address normalization |
| Service Layer | `services.py` (~2190 lines) | COM vtable implementations: IDebuggerServices, ILLDBServices, IHost, IHostServices, ITarget, IRuntime, ICLRDataTarget2, DAC init |
| ABI Layer | `abi.py` (342 lines) | Vtable struct definitions for all COM interfaces, GUID/IID constants, C type definitions |
| Tracing | `tracing.py` (149 lines) | `sostrace` command, category filtering, env-var control |
| Native Bridge | `gdbbridge.cpp` (105 lines) | Extensions singleton, hosting init, command dispatch, IHost* exposure, PID update |
| Build System | `build.sh` (389 lines) | Builds diagnostics submodule + CMake native bridge |

### Command Dispatch Flow

1. User enters a command in GDB (e.g., `clrstack` or `sos clrstack`)
2. `SOSCommand.invoke()` is called
3. `lazy_load_sos()` loads `libsos.so` and bridge, initializes via `SOSInitializeByHost`
4. Pre-dispatch: attempt hosting init, update target PID, flush if needed
5. Try native export dispatch via SOS function pointer
6. If native not found, try managed dispatch via bridge/libsos forwarder
7. Handle errors with HRESULT hints

### Key Design Decisions

1. **Bridge co-location**: `libsosgdbbridge.so` must reside in the same directory as `libsos.so`, or hosting init fails (HRESULT 0x80070002)
2. **Eager hosting init**: Attempt to start managed hosting at libsos load time, mirroring LLDB's flow
3. **No Python host fallback**: If native host is unavailable, proceed with NULL host path; no Python fallback host is constructed
4. **Arch-aware**: Supports x64 and arm64 via GDB frame architecture, `show architecture`, and `os.uname()`
5. **Category-level tracing**: Tracing output is runtime-controllable via env vars and the `sostrace` GDB command
