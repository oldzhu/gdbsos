# CHANGELOG / 变更日志

---

## 中文 / zh-cn

本文档记录 gdbsos 项目的所有显著变更。

---

## [未发布] / [Unreleased]

### 新增 / Added
- **架构设计文档** — `docs/design/` 下的 6 份双语设计文档 (zh-cn + en)
- **CI/CD 工作流** — `.github/workflows/ci.yml` 在 push/PR 时自动构建和测试 x64 + arm64
- **测试覆盖率扩展** — 新增 20 个测试场景覆盖之前未测试的命令
- **插件框架** — 配置了 superpowers 和 oh-my-opencode 用于 AI 辅助开发
- **聊天跟踪** — `docs/chat/` 目录，按会话记录所有聊天交互

### 变更 / Changed
- **文档结构重组** — `docs/` 目录现在包含 `design/`、`changelog/`、`planning/`、`chat/` 子文件夹

---

## v0.1.x — 初始开发 / Initial Development

### 核心功能 / Core Features
- GDB Python 扩展，用于承载 .NET SOS 诊断命令
- 通过 Extensions 框架实现原生 C++ bridge（`libsosgdbbridge.so`）
- 60+ SOS 命令支持（原生导出 + 托管分发）
- Bridge 与 libsos.so 的共位策略
- x64 和 arm64 架构支持
- DT_CONTEXT 填充（AMD64 和 ARM64 布局）
- 分类级别跟踪系统（`sostrace` 命令）
- DAC 初始化（ICLRDataTarget2、CLRDataCreateInstance）
- 托管主机初始化（急切的 + 懒惰的入口点）
- 通过 `/proc/PID/maps` 自动检测 CoreCLR
- 32 个初始 GDB 集成测试场景
- QEMU ARM64 测试基础设施（本地开发）
- 开发和发布用的构建编排（`build.sh` + CMake）
- GitHub Actions 发布工作流（带 x64/arm64 打包的 `release.yml`）
- `.devcontainer/` 配置（amd64 和 arm64 服务）
- FAQ 和故障排除文档（W^X、构建、交换、部署）
- 地址规范化（无 `0x` 前缀的原始 hex → `0x` 前缀化）
- 内存转储包装器（db、dd、dq、dw、dc、du、da、dp、readmemory）
- LLDB 风格包装器（modules、lm、registers、r、threads、setthread、logopen、logclose）
- `sethostruntime` 命令
- `sos exec` 动态分发器
- `ext` 前缀别名
- WinDbg/cdb-only 命令的 `UnsupportedSosCommand` 存根
- 友好的 HRESULT 错误提示
- 自动 `sosflush`（在 CLR 加载转换时）
- C++ throw 断点处理（`__cxa_throw` / `__cxa_rethrow`）
- 停止事件挂钩（自动继续）
- 新的 objfile 事件挂钩（早期 CoreCLR 检测）
- 运行时加载回调（coreclr_execute_assembly 断点）
- 通过 `process_vm_readv` 进行的进程内内存读取（用于 DAC）
- 通过 GDB write_memory + core dump 检测进行的内存写入

---

## English / en

This document records all notable changes to the gdbsos project.

---

## [Unreleased]

### Added
- **Architecture Design Docs** — 6 bilingual design documents under `docs/design/` (zh-cn + en)
- **CI/CD Workflow** — `.github/workflows/ci.yml` auto-builds and tests x64 + arm64 on push/PR
- **Test Coverage Expansion** — 20 new test scenarios covering previously untested commands
- **Plugin Frameworks** — superpowers + oh-my-opencode configured for AI-assisted development
- **Chat Tracking** — `docs/chat/` directory records all chat interactions per session

### Changed
- **Docs restructured** — `docs/` now contains `design/`, `changelog/`, `planning/`, `chat/` subfolders

---

## v0.1.x — Initial Development

### Core Features
- GDB Python extension hosting .NET SOS diagnostics commands
- Native C++ bridge (`libsosgdbbridge.so`) via Extensions framework
- 60+ SOS commands (native exports + managed dispatch)
- Bridge co-location strategy with libsos.so
- x64 and arm64 architecture support
- DT_CONTEXT population (AMD64 and ARM64 layouts)
- Category-level tracing system (`sostrace` command)
- DAC initialization (ICLRDataTarget2, CLRDataCreateInstance)
- Managed hosting initialization (eager + lazy entry points)
- Automatic CoreCLR detection via `/proc/PID/maps`
- 32 initial GDB integration test scenarios
- QEMU ARM64 test infrastructure (local dev)
- Build orchestration for dev and release (`build.sh` + CMake)
- GitHub Actions release workflow (`release.yml` with x64/arm64 packaging)
- `.devcontainer/` configuration (amd64 and arm64 services)
- FAQ and troubleshooting docs (W^X, building, swapping, deploying)
- Address normalization (raw hex without `0x` prefix → `0x`-prefixed)
- Memory dump wrappers (db, dd, dq, dw, dc, du, da, dp, readmemory)
- LLDB-style wrappers (modules, lm, registers, r, threads, setthread, logopen, logclose)
- `sethostruntime` command
- `sos exec` fallback dispatcher
- `ext` prefix alias
- `UnsupportedSosCommand` stubs for WinDbg/cdb-only commands
- Friendly HRESULT error hints
- Automatic `sosflush` (on CLR load transition)
- C++ throw breakpoint handling (`__cxa_throw` / `__cxa_rethrow`)
- Stop event hook (auto-continue)
- New objfile event hook (early CoreCLR detection)
- Runtime loaded callback (coreclr_execute_assembly breakpoint)
- In-process memory read via `process_vm_readv` (for DAC)
- Memory write via GDB write_memory + core dump detection
