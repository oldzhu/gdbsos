# 06 — 跟踪与诊断子系统 / Tracing &amp; Diagnostics Subsystem

---

## 中文 / zh-cn

### 概述

跟踪子系统（`src/gdbplugin/sos/tracing.py`，149 行）为 Python 插件层提供了轻量级、有分类的调试输出机制。这对于诊断托管初始化问题、断点行为和内存访问模式至关重要，而无需修改源代码。

### 架构

```
环境变量                      GDB 命令
───────────                  ───────────
SOS_PY_TRACE=1 ──┐          sostrace on [cats]
SOS_PY_TRACE_     │          sostrace off [cats]
  CATEGORIES=...  ├──► 跟踪状态  ◄──  sostrace allow <cats>
SOS_PY_TRACE_     │    (全局)        sostrace status
  EXCLUDE=...   ──┘

跟踪状态
├── TRACE_ENABLED: bool
├── TRACE_CATEGORIES: set (包含列表 — 空 = 允许所有)
└── TRACE_EXCLUDE_CATEGORIES: set (排除优先)

跟踪 API
├── trace(msg)         → 使用类别 'misc'
├── trace_cat(cat, msg) → 使用特定类别
└── _trace_allowed(cat)  → 检查是否允许类别
```

### 类别列表

| 类别 | 描述 | 默认状态 |
|----------|-------------|---------------|
| `bpmd` | 断点/托管断点操作 | 允许 |
| `arch` | 架构检测 | 允许 |
| `disasm` | 反汇编操作 | 允许 |
| `help` | 帮助命令流程 | 允许 |
| `gen` | 生成的代码/帮助合并 | 允许 |
| `read` | 内存读取操作 | **默认排除**（噪声很大） |
| `output` | 格式化字符串输出（va_list） | **默认排除**（噪声很大） |
| `interrupt` | 用户中断检查 | **默认排除**（噪声很大） |
| `write` | 内存写入操作 | 允许 |
| `newobj` | 新 objfile 加载事件 | 允许 |
| `stop` | 停止事件处理 | 允许 |
| `misc` | 默认/旧版（`trace()` 调用） | 允许 |

### 排除机制

三个类别默认被抑制，因为它们在正常操作期间会产生大量输出：
- **`read`**: 每次 `read_virtual` 和 `_dt_read_virtual` 调用
- **`output`**: 每次 `lldb_output_va_list` 调用（SOS 每输出一行就调用一次）
- **`interrupt`**: 每次 `lldb_get_interrupt` 调用（高频轮询）

要在不重启的情况下重新启用：
```
(gdb) sostrace allow read
(gdb) sostrace allow output interrupt
```

### `sostrace` 命令

实现为 `SOSTraceCommand`（一个 GDB 命令），`sostrace` 操作跟踪配置：

| 子命令 | 效果 |
|-----------|--------|
| `sostrace on` | 通过 `SOS_PY_TRACE=1` 启用跟踪 |
| `sostrace on <cats>` | 启用并设置包含列表（仅显示这些类别） |
| `sostrace off` | 完全禁用跟踪 |
| `sostrace off <cats>` | 将类别添加到排除集（其他保持开启） |
| `sostrace allow <cats>` | 从排除集中移除类别 |
| `sostrace status` | 显示当前状态 + 包含/排除列表 |
| `sostrace cats` | 仅显示包含类别 |

### 使用示例

```
# 调试 bpmd 断点问题
(gdb) sostrace on bpmd
(gdb) bpmd MyApp.dll MyClass.MyMethod

# 调试架构检测
(gdb) sostrace on arch,disasm
(gdb) clrstack

# 调试托管初始化失败
(gdb) sostrace on bpmd,stop,newobj
(gdb) clrstack

# 暂时抑制噪声类别
(gdb) sostrace off read,output,interrupt

# 重新启用读取跟踪
(gdb) sostrace allow read
```

### 环境变量

| 变量 | 效果 |
|----------|--------|
| `SOS_PY_TRACE=1` | 全局启用跟踪（在 `sos.py` 导入时） |
| `SOS_PY_TRACE_CATEGORIES=cat1,cat2` | 设置包含列表（空 = 显示所有） |
| `SOS_PY_TRACE_EXCLUDE=cat1,cat2` | 设置排除列表（默认 += read,output,interrupt） |

---

## English / en

### Overview

The tracing subsystem (`src/gdbplugin/sos/tracing.py`, 149 lines) provides a lightweight, category-based debug output mechanism for the Python plugin layer. It is critical for diagnosing hosting initialization issues, breakpoint behavior, and memory access patterns without modifying source code.

### Architecture (see diagram above)

### Category List

| Category | Description | Default State |
|----------|-------------|---------------|
| `bpmd` | Breakpoint/managed breakpoint operations | Allowed |
| `arch` | Architecture detection | Allowed |
| `disasm` | Disassembly operations | Allowed |
| `help` | Help command flow | Allowed |
| `gen` | Generated code/help merging | Allowed |
| `read` | Memory read operations | **Excluded by default** (very noisy) |
| `output` | Formatted string output (va_list) | **Excluded by default** (very noisy) |
| `interrupt` | User interrupt checking | **Excluded by default** (very noisy) |
| `write` | Memory write operations | Allowed |
| `newobj` | New objfile load events | Allowed |
| `stop` | Stop event handling | Allowed |
| `misc` | Default/legacy (`trace()` calls) | Allowed |

### Exclusion Mechanism

Three categories are suppressed by default because they generate enormous output during normal operation:
- **`read`**: Every `read_virtual` and `_dt_read_virtual` call
- **`output`**: Every `lldb_output_va_list` call
- **`interrupt`**: Every `lldb_get_interrupt` call (high-frequency polling)

To re-enable without restarting: `sostrace allow read`

### The `sostrace` Command

| Subcommand | Effect |
|-----------|--------|
| `sostrace on` | Enable tracing via `SOS_PY_TRACE=1` |
| `sostrace on <cats>` | Enable and set include list |
| `sostrace off` | Disable tracing entirely |
| `sostrace off <cats>` | Add categories to exclude set |
| `sostrace allow <cats>` | Remove categories from exclude set |
| `sostrace status` | Show current state + include/exclude lists |
| `sostrace cats` | Show include categories only |

### Environment Variables

| Variable | Effect |
|----------|--------|
| `SOS_PY_TRACE=1` | Enable tracing globally (at sos.py import time) |
| `SOS_PY_TRACE_CATEGORIES=cat1,cat2` | Set include list |
| `SOS_PY_TRACE_EXCLUDE=cat1,cat2` | Set exclude list |
