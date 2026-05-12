# 02 — 原生桥接架构 / Native Bridge Architecture

---

## 中文 / zh-cn

### 概述

原生桥接 `libsosgdbbridge.so` 是一个轻量级的 C++ 共享库，使用诊断子模块（`src/diagnostics/`）中的 `Extensions` 框架。它充当 Python 插件层与 .NET 托管诊断基础设施之间的适配器。

**源文件**: `src/gdbplugin/bridge/gdbbridge.cpp` (105 行)
**构建**: `src/gdbplugin/bridge/CMakeLists.txt` — 针对 `libextensions.a` 链接，使用 C++17

### 架构

```
┌──────────────────────────────────────────────────┐
│              libsosgdbbridge.so                   │
│                                                   │
│  ┌─────────────────────────────────────────────┐ │
│  │  GdbPluginExtensions : Extensions           │ │
│  │  - 拥有单例                                  │ │
│  │  - 持有 IHost* (m_pHost)                    │ │
│  │  - GetHost() 覆盖                           │ │
│  └─────────────────────────────────────────────┘ │
│                                                   │
│  导出的 C 函数 (visibility("default")):          │
│  ┌─────────────────────────────────────────────┐ │
│  │ InitGdbExtensions(debuggerServices)          │ │
│  │ InitManagedHosting(runtimeDir, majorVersion) │ │
│  │ DispatchManagedCommand(cmdName, args)        │ │
│  │ GetHostForSos() → void* (IHost*)             │ │
│  │ UpdateManagedTarget(processId)               │ │
│  └─────────────────────────────────────────────┘ │
└───────────────────┬──────────────────────────────┘
                    │ 链接到
                    ▼
┌──────────────────────────────────────────────────┐
│          libextensions.a (诊断子模块)             │
│  Extensions 类, IHost, IHostServices,            │
│  InitializeHosting(), GetHostServices(),          │
│  SetHostRuntime(), UpdateTarget()                 │
└──────────────────────────────────────────────────┘
```

### 导出函数详解

#### `InitGdbExtensions(IDebuggerServices* debuggerServices)`
- **用途**: 使用提供的调试器服务指针创建 `Extensions` 单例
- **调用时机**: 在 libsos 加载期间，调用 `SOSInitializeByHost` 之前
- **返回**: 成功返回 0

#### `InitManagedHosting(const char* runtimeDir, int majorVersion)`
- **用途**: 初始化托管 CLI 主机环境
- **参数**:
  - `runtimeDir`: .NET 运行时目录的可选路径（可为 NULL）
  - `majorVersion`: 可选的运行时主版本（0 表示默认）
- **流程**:
  1. 验证 Extensions 单例是否存在（如果没有，返回 E_NOINTERFACE）
  2. 如果已初始化则跳过（幂等）
  3. 如果提供了目录或版本，调用 `SetHostRuntime()`
  4. 调用 `Extensions::InitializeHosting()`
  5. 标记 `g_hostingInitialized = true`
- **返回**: 成功返回 0，失败返回 HRESULT

#### `DispatchManagedCommand(const char* cmd, const char* args)`
- **用途**: 将命令字符串转发给托管主机服务进行执行
- **流程**:
  1. 获取 `IHostServices` 指针
  2. 如果为 null，按需初始化托管
  3. 调用 `hostServices->DispatchCommand(commandName, arguments, true)`
- **返回**: 成功返回 0，错误返回 HRESULT

#### `GetHostForSos()`
- **用途**: 返回原生 `IHost*` 指针，以传递给 `SOSInitializeByHost`
- **返回**: `IHost*` 指针，如果 Extensions 未初始化则返回 NULL
- **调用时机**: 由 `sos.py` 在 SOS 初始化期间调用

#### `UpdateManagedTarget(unsigned int processId)`
- **用途**: 强制托管主机为给定 PID 创建或更新目标进程
- **流程**:
  1. 验证 Extensions 单例是否存在
  2. 必要时按需初始化托管
  3. 调用 `Extensions::UpdateTarget(processId)`
- **返回**: 成功返回 0，错误返回 HRESULT

### 共位策略

Bridge 必须通过 `_ensure_bridge_colocated()` 与 `libsos.so` 共位：
1. 确定 `libsos.so` 目录
2. 如果 bridge 已存在，直接使用
3. 否则从插件目录复制（使用大小/mtime 比较避免不必要的复制）
4. 如果共位不可行，回退到从插件目录直接加载（带警告）

**原因**: `InitManagedHosting` 在 bridge 和 `libsos.so` 位于同一目录时才能可靠成功。非共位加载会导致 HRESULT 0x80070002 (E_FILE_NOT_FOUND)。

---

## English / en

### Overview

The native bridge `libsosgdbbridge.so` is a lightweight C++ shared library that uses the `Extensions` framework from the diagnostics submodule (`src/diagnostics/`). It acts as the adapter between the Python plugin layer and the .NET managed diagnostics infrastructure.

**Source**: `src/gdbplugin/bridge/gdbbridge.cpp` (105 lines)
**Build**: `src/gdbplugin/bridge/CMakeLists.txt` — links against `libextensions.a`, C++17

### Architecture (see diagram above)

### Exported Functions Detail

#### `InitGdbExtensions(IDebuggerServices* debuggerServices)`
- **Purpose**: Create the `Extensions` singleton with the provided debugger services pointer
- **Called during**: libsos loading, before `SOSInitializeByHost`
- **Returns**: 0 on success

#### `InitManagedHosting(const char* runtimeDir, int majorVersion)`
- **Purpose**: Initialize the managed CLI hosting environment
- **Flow**:
  1. Verify Extensions singleton exists
  2. Skip if already initialized (idempotent)
  3. If directory/version provided, call `SetHostRuntime()`
  4. Call `Extensions::InitializeHosting()`
  5. Mark `g_hostingInitialized = true`
- **Returns**: 0 on success, HRESULT on failure

#### `DispatchManagedCommand(const char* cmd, const char* args)`
- **Purpose**: Forward a command string to the managed host services
- **Returns**: 0 on success, HRESULT on error

#### `GetHostForSos()`
- **Purpose**: Return the native `IHost*` pointer for passing to `SOSInitializeByHost`
- **Returns**: `IHost*` pointer, or NULL if Extensions not initialized

#### `UpdateManagedTarget(unsigned int processId)`
- **Purpose**: Force the managed host to create/update the target process for the given PID
- **Returns**: 0 on success, HRESULT on error

### Co-Location Strategy

The bridge MUST be co-located with `libsos.so` via `_ensure_bridge_colocated()`:
1. Determine `libsos.so` directory
2. If bridge already there, use it
3. Otherwise copy from plugin directory (with size/mtime comparison)
4. Fallback to direct load from plugin dir with a warning

**Reason**: `InitManagedHosting` succeeds reliably only when bridge and `libsos.so` reside in the same directory. Non-co-located loading results in HRESULT 0x80070002.
