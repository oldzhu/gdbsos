# 05 — 架构检测与 ABI 处理 / Architecture Detection &amp; ABI Handling

---

## 中文 / zh-cn

### 概述

gdbsos 插件支持 x64 (AMD64) 和 ARM64 (AArch64) 架构。架构在运行时通过多种来源检测，并传播到 SOS 原生库以进行正确的对等（pointer size、machine type 和 DT_CONTEXT 填充）。

### 检测链

```
_detect_arch_name()
    │
    ├── 1) GDB frame.architecture().name()
    │      例: 'i386:x86-64', 'aarch64'
    │
    ├── 2) 'show architecture' GDB 命令
    │      解析: "currently <arch>)"
    │
    └── 3) os.uname().machine
           例: 'x86_64', 'aarch64'
    │
    ▼
_detect_machine_type()
    │
    ├── 环境覆盖: SOS_FORCE_MACHINE_TYPE / SOS_FORCE_ARCH
    │      值: 'arm64', 'aarch64' → IMAGE_FILE_MACHINE_ARM64 (0xAA64)
    │           'amd64', 'x64', 'x86_64' → IMAGE_FILE_MACHINE_AMD64 (0x8664)
    │
    ├── 名称匹配: 'aarch64'/'arm64' → ARM64
    │             'x86-64'/'amd64'/'i386:x86-64' → AMD64
    │
    └── 回退: ctypes.sizeof(c_void_p) == 8 → AMD64
    │
    ▼
_detect_pointer_size()
    │
    ├── 1) GDB lookup_type('void').pointer().sizeof
    └── 2) ctypes.sizeof(ctypes.c_void_p) (回退)
```

### 检测的使用位置

| 消费者 | 方法 | 目的 |
|---------|------|------|
| DAC 目标 | `_dt_get_machine_type()` | 向 CLRDataCreateInstance 返回 IMAGE_FILE_MACHINE_* |
| DAC 目标 | `_dt_get_pointer_size()` | 返回指针大小 (8) |
| 调试器服务 | `lldb_get_processor_type()` | 向 SOS 返回处理器类型 |
| 反汇编 | `lldb_disassemble()` | 选择反汇编策略 (x64 的 Intel 风味，arm64 的固定 4 字节) |
| DT_CONTEXT | `_fill_amd64_dt_context()` | 用 GDB 寄存器值填充 AMD64 DT_CONTEXT |
| DT_CONTEXT | `_fill_arm64_dt_context()` | 用 GDB 寄存器值填充 ARM64 DT_CONTEXT |

### DT_CONTEXT 填充

#### AMD64 布局 (`_fill_amd64_dt_context`)
```
偏移    字段    来源 (GDB reg)
─────────────────────────────────
+0x78   Rax     rax
+0x80   Rcx     rcx
+0x88   Rdx     rdx
+0x90   Rbx     rbx
+0x98   Rsp     rsp
+0xA0   Rbp     rbp
+0xA8   Rsi     rsi
+0xB0   Rdi     rdi
+0xB8   R8      r8
+0xC0   R9      r9
+0xC8   R10     r10
+0xD0   R11     r11
+0xD8   R12     r12
+0xE0   R13     r13
+0xE8   R14     r14
+0xF0   R15     r15
+0xF8   Rip     rip
```

#### ARM64 布局 (`_fill_arm64_dt_context`)
```
偏移    字段            来源 (GDB reg)
─────────────────────────────────────────
+0x00   ContextFlags     contextFlags 参数
+0x04   Cpsr            cpsr / pstate
+0x08   X0..X28         x0..x28
+0xF0   Fp (x29)        x29 / fp
+0xF8   Lr (x30)        x30 / lr
+0x100  Sp              sp
+0x108  Pc              pc
```

### 反汇编策略

| 环境条件 | 策略 |
|------------|----------|
| `SOS_GDB_USE_PY_DISASM=1` | 使用 GDB Python `arch.disassemble()` API |
| AMD64 + 默认 | 保存风味，切换到 Intel，使用 `x/2i`，计算指令长度，恢复风味 |
| ARM64 + 默认 | 固定 4 字节指令；使用 `x/1i`，提取文本 |

### 文件结构

**源文件**: `src/gdbplugin/sos/abi.py` (342 行)

`abi.py` 定义了所有的 C 类型、GUID/IID 常量和用于 COM 接口的 vtable 结构体布局。关键定义：

- **基本类型**: `HRESULT`, `ULONG`, `ULONG64`, `PVOID`, `PCSTR`, `LPCWSTR`
- **GUID/IID**: 所有接口标识符，以大端序格式定义
- **Vtable 结构体**: `IUnknownVtbl`, `IDebuggerServicesVtbl`, `ILLDBServicesVtbl`, `ILLDBServices2Vtbl`, `IHostVtbl`, `IHostServicesVtbl`, `ITargetVtbl`, `IRuntimeVtbl`, `ICLRDataTarget2Vtbl`
- **接口包装器**: `IDebuggerServices`, `ILLDBServices`, `IHost`, `IHostServices`, `ITarget`, `IRuntime`, `IMemoryService`, `ICLRDataTarget2`
- **函数指针类型**: 所有 vtable 方法的 `CFUNCTYPE` 定义

---

## English / en

### Overview

The gdbsos plugin supports both x64 (AMD64) and ARM64 (AArch64) architectures. Architecture is detected at runtime from multiple sources and propagated to the SOS native library for correct parity (pointer size, machine type, and DT_CONTEXT population).

### Detection Chain (see diagram above)

### Where Detection Is Used

| Consumer | Method | Purpose |
|----------|--------|---------|
| DAC target | `_dt_get_machine_type()` | Return IMAGE_FILE_MACHINE_* to CLRDataCreateInstance |
| DAC target | `_dt_get_pointer_size()` | Return pointer size (8) |
| Debugger services | `lldb_get_processor_type()` | Return processor type to SOS |
| Disassembly | `lldb_disassemble()` | Choose disassembly strategy (Intel flavor for x64, fixed 4-byte for arm64) |
| DT_CONTEXT | `_fill_amd64_dt_context()` | Populate AMD64 DT_CONTEXT from GDB register values |
| DT_CONTEXT | `_fill_arm64_dt_context()` | Populate ARM64 DT_CONTEXT from GDB register values |

### DT_CONTEXT Population (see layout tables above)

### Disassembly Strategy

| Condition | Strategy |
|-----------|----------|
| `SOS_GDB_USE_PY_DISASM=1` | Use GDB Python `arch.disassemble()` API |
| AMD64 + default | Save flavor, switch to Intel, use `x/2i`, compute instruction length, restore flavor |
| ARM64 + default | Fixed 4-byte instructions; use `x/1i`, extract text |

### File Structure

**Source file**: `src/gdbplugin/sos/abi.py` (342 lines)

`abi.py` defines all C types, GUID/IID constants, and vtable struct layouts for COM interfaces. Key definitions:

- **Basic types**: `HRESULT`, `ULONG`, `ULONG64`, `PVOID`, `PCSTR`, `LPCWSTR`
- **GUID/IID**: All interface identifiers
- **Vtable structs**: All COM interface vtables
- **Interface wrappers**: Struct wrappers with `lpVtbl` pointers
- **Function pointer types**: `CFUNCTYPE` definitions for all vtable methods
