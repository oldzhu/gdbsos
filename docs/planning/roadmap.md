# Roadmap / 路线图

---

## 中文 / zh-cn

### 当前版本: v0.1.x

### 近期计划 (v0.2.x)
- [ ] 在 CI 测试中稳定所有新场景（52 个场景）
- [ ] 为 CLR 加载失败添加更好的错误处理
- [ ] 支持 `dumpheap -stat` 和 `dumpheap -type` 变体
- [ ] 改进托管命令的超时处理
- [ ] 为 symbol server 配置添加测试

### 中期计划 (v0.3.x)
- [ ] 启动时自动检测和管理 CoreCLR 运行时版本
- [ ] 改进 arm64 的反汇编质量
- [ ] 支持核心 dump 文件分析（增强模式）
- [ ] 添加 `sos status` 仪表盘（内存、线程、GC 统计）
- [ ] 用于生产诊断的 OpenTelemetry 集成

### 长期计划 (v0.4.x+)
- [ ] 为 S390x/ppc64le 提供实验性支持
- [ ] 自定义 GDB 仪表盘的 TUI 模式
- [ ] 与 `dotnet-dump` 分析器集成
- [ ] macOS 支持（lldb 桥接 + GDB）
- [ ] 插件的 C# 重写（利用原生互操作）

### 基础设施
- [x] CI 工作流 (push/PR: x64 + arm64)
- [x] 发布工作流 (标签: x64 + arm64 打包)
- [x] 架构设计文档 (双语)
- [x] 测试覆盖率 (52 个场景)
- [ ] 集成基准测试
- [ ] 代码覆盖率报告

---

## English / en

### Current: v0.1.x

### Short Term (v0.2.x)
- [ ] Stabilize all new scenarios in CI testing (52 scenarios)
- [ ] Better error handling for CLR load failures
- [ ] Support `dumpheap -stat` and `dumpheap -type` variants
- [ ] Improved timeout handling for managed commands
- [ ] Tests for symbol server configuration

### Medium Term (v0.3.x)
- [ ] Auto-detect and manage CoreCLR runtime version at startup
- [ ] Improved disassembly quality for arm64
- [ ] Core dump file analysis support (enhanced mode)
- [ ] Add `sos status` dashboard (memory, threads, GC stats)
- [ ] OpenTelemetry integration for production diagnostics

### Long Term (v0.4.x+)
- [ ] Experimental support for S390x/ppc64le
- [ ] TUI mode for custom GDB dashboards
- [ ] Integration with `dotnet-dump` analyzer
- [ ] macOS support (lldb bridge + GDB)
- [ ] C# rewrite of plugin (leveraging native interop)

### Infrastructure
- [x] CI workflow (push/PR: x64 + arm64)
- [x] Release workflow (tags: x64 + arm64 packaging)
- [x] Architecture design docs (bilingual)
- [x] Test coverage (52 scenarios)
- [ ] Integration benchmarks
- [ ] Code coverage reports
