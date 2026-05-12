# 04 — 托管主机初始化流程 / Managed Hosting Initialization Flow

---

## 中文 / zh-cn

### 概述

在 SOS 命令可以使用 .NET 托管诊断功能（如 `dumpheap`、`clrstack` 的托管变体、`soshelp` 的托管变体等）之前，必须初始化托管主机环境。本文档详细介绍了初始化顺序、错误处理和 PID 传播。

### 完整初始化流程

```
[1] 首次命令调用
    │
    ▼
[2] SOSCommand.lazy_load_sos()
    ├── 发现 libsos.so（SOS_ROOT → ~/.dotnet/sos → 插件目录）
    ├── 与 libsos.so 共位 libsosgdbbridge.so
    ├── 加载 bridge ctypes.CDLL（RTLD_GLOBAL）
    ├── 加载 libsos ctypes.CDLL
    └── 创建 GdbServices 实例
    │
    ▼
[3] Bridge InitGdbExtensions(debuggerServices)
    └── 使用调试器服务创建 GdbPluginExtensions 单例
    │
    ▼
[4] Eager InitManagedHosting(NULL, 0)
    ├── [仅在 SOS_GDB_USE_HOST != 0 时]
    ├── 设置 Extensions 单例中的主机运行时
    └── 调用 Extensions::InitializeHosting()
    │
    ▼
[5] GetHostForSos()
    └── 返回原生 IHost* (或 NULL)
    │
    ▼
[6] SOSInitializeByHost(host, debuggerServices)
    ├── 如果可用，传递原生 IHost*
    ├── 如果不可用，传递 NULL（无 Python 回退）
    └── SOS 库通过 debuggerServices 准备好回调
    │
    ▼
[7] 单次命令调用（预分发）
    ├── 检查 libcoreclr.so 是否已加载
    ├── 如果已加载：调用 InitManagedHosting + UpdateManagedTarget(pid)
    ├── 如果刚加载：调用 _maybe_flush_after_runtime_load()
    └── 分发命令
    │
    ▼
[8] 运行时加载事件（异步）
    ├── new_objfile 钩子检测 libcoreclr.so
    ├── runtime_loaded 回调在 coreclr_execute_assembly 触发
    ├── 托管初始化 + PID 更新
    └── 自动继续
```

### 时间线和入口点

| 阶段 | 触发器 | 动作 |
|------|--------|------|
| **急切初始化** | `lazy_load_sos()`, 步骤 4 | `InitManagedHosting(NULL, 0)` 尝试原生 IHost* |
| **预分发** | 每个命令调用 | 如果 CLR 已加载，调用 `InitManagedHosting` + `UpdateManagedTarget(pid)` |
| **objfile 钩子** | `libcoreclr.so` 出现在 /proc/PID/maps 中 | `InitManagedHosting` + `UpdateManagedTarget` |
| **运行时入口** | 命中断点 `coreclr_execute_assembly` | 触发 `runtime_loaded_cb`，初始化托管，更新 PID |
| **刷新** | CLR 从 "not loaded" 转变为 "loaded" | 单次调用 `sosflush` 清除 SOS 缓存 |
| **手动** | `sethostruntime [-major N] [目录]` | 用户手动初始化（指定目录和版本） |

### 错误处理和 HRESULT 提示

| HRESULT | 含义 | 提示 |
|---------|------|------|
| `0x80070002` | 文件未找到 | Bridge 未与 libsos.so 共位 |
| `0x80004002` | 无接口 | Extensions 单例在 `InitGdbExtensions` 调用前缺失 |
| `0x80004005` | 未指定的故障 | Hosting init 失败；尝试 `sostrace on` |
| `0x80070057` | 无效参数 | 检查命令选项 |
| `0x8007000E` | 内存不足 | — |
| `0x80070005` | 拒绝访问 | 内存读取失败 |
| `0` (S_OK) | 成功 | — |

### PID 传播

`UpdateManagedTarget(pid)` 将当前被调试进程的 PID 传播到托管主机。这对于托管主机枚举目标中的 CLR 运行时至关重要。它在以下位置被调用：

1. `lazy_load_sos()` 中，在 SOS 初始化后（对急切初始化）
2. 每个命令调用之前的预分发检查（对延迟初始化）
3. 运行时加载事件（objfile 钩子，运行时入口断点）
4. `_maybe_flush_after_runtime_load()` 过渡

### 环境变量门控

| 变量 | 默认值 | 效果 |
|------|--------|------|
| `SOS_GDB_USE_HOST` | `1` | 启用原生 IHost* 路径（设置为 0 以恢复为 NULL 主机） |
| `SOS_ROOT` | 未设置 | 覆盖 libsos.so 搜索路径 |
| `SOS_FORCE_MACHINE_TYPE` | 未设置 | 覆盖机器类型检测 |

### 设计决策原理

1. **急切初始化 > 延迟初始化**: 我们在 libsos 加载时尝试托管初始化，以并行 LLDB 行为。这避免了复杂的延迟初始化状态管理。如果急切初始化失败，预分发重试提供回退。

2. **无 Python 主机回退**: 构造 Python 实现的 IHost 会创建一个重复的宿主环境，可能导致状态损坏。NULL 主机路径清楚地表明出了问题。

3. **共位是强制性的**: 与 libsos.so 位于同一目录的 bridge 是可靠性所必需的。任何覆盖此设定的环境变量只会隐藏问题。

---

## English / en

### Overview

Before SOS commands can use .NET managed diagnostics features, the managed hosting environment must be initialized. This document details the initialization sequence, error handling, and PID propagation.

### Full Initialization Flow (see diagram above)

### Timeline and Entry Points

| Stage | Trigger | Action |
|-------|---------|--------|
| **Eager init** | `lazy_load_sos()`, step 4 | `InitManagedHosting(NULL, 0)` attempt for native IHost* |
| **Pre-dispatch** | Each command invocation | If CLR loaded, call `InitManagedHosting` + `UpdateManagedTarget(pid)` |
| **objfile hook** | `libcoreclr.so` appears in /proc/PID/maps | `InitManagedHosting` + `UpdateManagedTarget` |
| **Runtime entry** | Breakpoint hit at `coreclr_execute_assembly` | Fire `runtime_loaded_cb`, init hosting, update PID |
| **Flush** | CLR transitions from "not loaded" to "loaded" | One-time `sosflush` call to clear SOS caches |
| **Manual** | `sethostruntime [-major N] [dir]` | User manual init (with directory and version) |

### Error Handling and HRESULT Hints

| HRESULT | Meaning | Hint |
|---------|---------|------|
| `0x80070002` | File not found | Bridge not co-located with libsos.so |
| `0x80004002` | No interface | Extensions singleton missing before `InitGdbExtensions` |
| `0x80004005` | Unspecified failure | Hosting init failed; try `sostrace on` |
| `0x80070057` | Invalid argument | Check command options |
| `0x8007000E` | Out of memory | — |
| `0x80070005` | Access denied | Memory read failed |
| `0` (S_OK) | Success | — |

### PID Propagation

`UpdateManagedTarget(pid)` propagates the PID of the currently debugged process to the managed host. This is critical for the managed host to enumerate CLR runtimes in the target. It is called at:

1. In `lazy_load_sos()`, after SOS initialization (for eager init)
2. Pre-dispatch check before each command invocation (for lazy init)
3. Runtime load events (objfile hook, runtime entry breakpoint)
4. `_maybe_flush_after_runtime_load()` transition

### Environment Variable Gates

| Variable | Default | Effect |
|----------|---------|--------|
| `SOS_GDB_USE_HOST` | `1` | Enable native IHost* path (set to 0 for NULL host fallback) |
| `SOS_ROOT` | unset | Override libsos.so search path |
| `SOS_FORCE_MACHINE_TYPE` | unset | Override machine type detection |

### Design Decision Rationale

1. **Eager over lazy init**: We attempt hosting init at libsos load time to parallel LLDB behavior. Pre-dispatch retries provide fallback.
2. **No Python host fallback**: Constructing a Python-implemented IHost creates a duplicate hosting environment. NULL host path surfaces the issue clearly.
3. **Co-location is mandatory**: Bridge in same directory as libsos.so is required for reliability. Any env override only hides problems.
