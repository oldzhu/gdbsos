# 03 — 插件服务层 / Plugin Services Layer

---

## 中文 / zh-cn

### 概述

Python 插件服务层（`src/gdbplugin/sos/services.py`，约 2190 行）实现了 SOS 诊断扩展所需的所有 COM 风格接口。这些接口使 SOS 原生库能够调用回调试器以进行内存访问、模块枚举、线程上下文检索、输出和命令执行。

### 实现的接口

| 接口 | 实现类 | 用途 |
|------|--------|------|
| **IUnknown** | `GdbServices` | 引用计数，`QueryInterface` 路由 |
| **IDebuggerServices** | `GdbServices` (vtable) | 调试器能力：模块、线程、符号、内存、输出 |
| **IMemoryService** | `GdbServices` (vtable) | 原始内存读取（分页，跨越页面边界） |
| **ILLDBServices** | `GdbServices` (vtable) | LLDB 风格服务：CoreCLR 目录、表达式、执行、反汇编 |
| **ILLDBServices2** | `GdbServices` (vtable) | 扩展服务：原生符号、运行时回调 |
| **IHost** | `GdbServices` (vtable) | 主机类型标识，服务解析，当前目标检索 |
| **IHostServices** | `GdbServices` (vtable) | 主机生命周期：注册、创建目标、更新、刷新、销毁、取消初始化 |
| **ITarget** (原生) | `GdbServices` (vtable) | 目标操作系统，服务解析，运行时检索 |
| **IRuntime** (原生) | `GdbServices` (vtable) | 运行时配置、模块地址/大小、DAC 初始化、EE 版本 |
| **ICLRDataTarget2** | `GdbServices` (vtable) | DAC 目标接口：机器类型、指针大小、读/写虚拟内存、线程上下文 |

### 关键实现细节

#### QueryInterface 路由
```
调用者 → QueryInterface(IID)
  ├── IID_IUnknown / IID_IDebuggerServices → IDebuggerServices*
  ├── IID_IMemoryService → IMemoryService*
  ├── IID_IHost → IHost*
  ├── IID_ILLDBServices → ILLDBServices*
  ├── IID_ILLDBServices2 → ILLDBServices2*
  └── 其他 → E_NOINTERFACE (0x80004002)
```

#### 内存读取 (`read_virtual`)
- 实现跨页面边界的块读取，每次内存访问限制在 4096 字节以内
- 遇到 `gdb.MemoryError` 时逐步回退到较小的读取大小
- 不支持回退的不可读区域，直接跳过
- 返回实际读取的字节数

#### CoreCLR 扫描 (`_scan_coreclr`)
- 解析 `/proc/{pid}/maps` 以在目标进程中找到 `libcoreclr.so`
- 提取基地址和路径，缓存以备后用
- 如果映射了多个段，返回最低的起始地址
- 优雅地处理 ` (deleted)` 后缀

#### DT_CONTEXT 填充
- **AMD64** (`_fill_amd64_dt_context`): 映射 GDB 寄存器名称（rip/rsp/rbp/rax..r15）到 DT_CONTEXT 结构字段
- **ARM64** (`_fill_arm64_dt_context`): 映射 GDB 寄存器名称（x0..x28, x29/fp, x30/lr, sp, pc, cpsr/pstate）到 ARM64 DT_CONTEXT 布局

#### 架构检测
- 主入口: `_detect_arch_name()` → `_detect_machine_type()` → `_detect_pointer_size()`
- 来源: GDB `frame.architecture().name()`，后备到 `show architecture`, `os.uname().machine`
- 机器类型: 映射 `aarch64`/`x86-64` → `IMAGE_FILE_MACHINE_ARM64`/`IMAGE_FILE_MACHINE_AMD64`
- 环境覆盖: `SOS_FORCE_MACHINE_TYPE` / `SOS_FORCE_ARCH`

#### 输出 (`lldb_output_va_list`)
- 使用 libc `vsnprintf` 将格式化字符串渲染到缓冲区
- 自动扩展缓冲区处理溢出
- 通过 `_interrupted` 标志支持用户中断（分页器退出的 'q'）

#### DAC 初始化 (`runtime_get_clr_data_process`)
- 从 CoreCLR 运行时目录加载 `libmscordaccore.so`
- 解析 `CLRDataCreateInstance`
- 使用 `ICLRDataTarget2` vtable 指针调用，接收 `IXCLRDataProcess*`
- 缓存 DAC 句柄和 CLR 数据进程以供后续使用

### SOS 初始化流程（从 sos.py）

1. `lazy_load_sos()` 被首次命令调用触发
2. 通过 `SOS_ROOT`、`~/.dotnet/sos` 或插件目录发现 `libsos.so`
3. Bridge 通过 `_ensure_bridge_colocated()` 共位
4. Bridge 以 `RTLD_GLOBAL`（如果可用）加载为 `ctypes.CDLL`
5. libsos 加载为 `ctypes.CDLL`
6. 使用 Python vtable 实现创建 `GdbServices` 实例
7. 调用 `InitGdbExtensions()` 来初始化 Extensions 单例
8. 急切尝试 `InitManagedHosting()` 以获取原生 IHost*
9. 调用 `SOSInitializeByHost(host, debuggerServices)`
10. 可选转发器已解析: `SOS_InitManagedHosting`, `SOS_DispatchManagedCommand`

### 事件处理

#### 新 objfile 钩子
- 在 GdbServices `__init__` 中主动注册
- 检测 `libcoreclr.so` 加载事件
- 触发: 托管初始化 + 托管目标 PID 更新
- 触发后单次自我解除连接

#### 停止事件钩子
- 当 `SetExceptionCallback` 注册异常回调时连接
- 仅处理 C++ throw 停止（`__cxa_throw` / `__cxa_rethrow`）
- 在 `coreclr_execute_assembly` 入口标记运行时初始化
- 在异常回调后自动继续

#### 运行时加载回调
- 由 SOS 通过 `lldb2_set_runtime_loaded_callback` 注册
- 在 `coreclr_execute_assembly` 创建一个临时的 Python 断点
- 在停止时: 初始化托管，更新 PID，调用回调，自动继续

---

## English / en

### Overview

The Python plugin services layer (`src/gdbplugin/sos/services.py`, ~2190 lines) implements all the COM-style interfaces required by the SOS diagnostics extension. These interfaces enable the SOS native library to call back into the debugger for memory access, module enumeration, thread context retrieval, output, and command execution.

### Implemented Interfaces

| Interface | Implemented By | Purpose |
|-----------|---------------|---------|
| **IUnknown** | `GdbServices` | Reference counting, `QueryInterface` routing |
| **IDebuggerServices** | `GdbServices` (vtable) | Debugger capabilities: modules, threads, symbols, memory, output |
| **IMemoryService** | `GdbServices` (vtable) | Raw memory reads (paged, cross-boundary) |
| **ILLDBServices** | `GdbServices` (vtable) | LLDB-style services: CoreCLR directory, expression, execute, disassemble |
| **ILLDBServices2** | `GdbServices` (vtable) | Extended services: native symbols, runtime callback |
| **IHost** | `GdbServices` (vtable) | Host type ID, service resolution, current target retrieval |
| **IHostServices** | `GdbServices` (vtable) | Host lifecycle: register, create target, update, flush, destroy, uninitialize |
| **ITarget** (native) | `GdbServices` (vtable) | Target OS, service resolution, runtime retrieval |
| **IRuntime** (native) | `GdbServices` (vtable) | Runtime config, module address/size, DAC init, EE version |
| **ICLRDataTarget2** | `GdbServices` (vtable) | DAC target interface: machine type, pointer size, read/write virtual, thread context |

### Key Implementation Details

#### Memory Read (`read_virtual`)
- Implements chunked reads across page boundaries, limiting each memory access to 4096 bytes
- Falls back to smaller read sizes progressively on `gdb.MemoryError`
- Skips unreadable regions gracefully
- Returns actual bytes read

#### CoreCLR Scanning (`_scan_coreclr`)
- Parses `/proc/{pid}/maps` to locate `libcoreclr.so` in the target process
- Extracts base address and path, cached for subsequent use
- Returns the lowest start address if multiple segments are mapped

#### DT_CONTEXT Population
- **AMD64** (`_fill_amd64_dt_context`): Maps GDB register names to DT_CONTEXT struct fields
- **ARM64** (`_fill_arm64_dt_context`): Maps GDB register names (x0..x28, fp, lr, sp, pc, cpsr/pstate)

#### Architecture Detection
- Primary: `_detect_arch_name()` → `_detect_machine_type()` → `_detect_pointer_size()`
- Sources: GDB `frame.architecture().name()`, fallback to `show architecture`, `os.uname().machine`
- Machine types: maps `aarch64`/`x86-64` → `IMAGE_FILE_MACHINE_ARM64`/`IMAGE_FILE_MACHINE_AMD64`
- Env overrides: `SOS_FORCE_MACHINE_TYPE` / `SOS_FORCE_ARCH`

#### Output (`lldb_output_va_list`)
- Uses libc `vsnprintf` to render formatted strings into a buffer
- Auto-expands buffer on overflow
- Supports user interruption via `_interrupted` flag

#### DAC Initialization (`runtime_get_clr_data_process`)
- Loads `libmscordaccore.so` from the CoreCLR runtime directory
- Resolves `CLRDataCreateInstance`
- Calls with `ICLRDataTarget2` vtable pointer, receives `IXCLRDataProcess*`
- Caches DAC handle and CLR data process

### SOS Initialization Flow (from sos.py)

1. `lazy_load_sos()` triggered by first command invocation
2. Discover `libsos.so` via `SOS_ROOT`, `~/.dotnet/sos`, or plugin directory
3. Bridge co-located via `_ensure_bridge_colocated()`
4. Bridge loaded as `ctypes.CDLL` with RTLD_GLOBAL
5. libsos loaded as `ctypes.CDLL`
6. `GdbServices` instance created with Python vtable implementations
7. `InitGdbExtensions()` called to initialize Extensions singleton
8. Eager `InitManagedHosting()` attempt for native IHost*
9. `SOSInitializeByHost(host, debuggerServices)` called
10. Optional forwarders resolved: `SOS_InitManagedHosting`, `SOS_DispatchManagedCommand`

### Event Handling

- **New objfile hook**: Detects `libcoreclr.so` load → hosting init + PID update
- **Stop event hook**: Handles C++ throw stops, marks runtime initialization at `coreclr_execute_assembly`
- **Runtime loaded callback**: Temporary breakpoint at `coreclr_execute_assembly` → init hosting → update PID → invoke callback → auto-continue
