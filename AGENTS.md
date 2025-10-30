# AGENTS.md

This document describes how automated agents (bots and AI coding assistants) should interact with this repository, what tasks are encouraged, and what guardrails apply. It is intended to enable safe, repeatable automation while keeping the codebase healthy.

## Purpose

- Explain the kinds of tasks agents can perform in this repo (builds, tests, small fixes, release chores).
- Provide essential context, commands, and conventions so agents can work effectively and safely.
- Define boundaries for changes and security expectations (no secrets, minimal risk by default).

## Repository overview

- Project: GDB Python extension (“gdbsos”) to host the .NET SOS diagnostics extension under GDB.
- Key locations:
  - `src/gdbplugin/sos/` — primary Python sources (`sos.py`, `services.py`, `tracing.py`).
  - `src/gdbplugin/bridge/` — native bridge used for managed hosting (`libsosgdbbridge.so`).
  - `src/diagnostics/` and `src/runtime/` — vendored upstream sources; prefer not to modify without explicit instruction.
  - `artifacts/bin/linux.<arch>.<Config>/` — published script copies used by tests.
  - `src/tests/gdb/` — test harness and scenarios.

## Common agent tasks

Safe, encouraged tasks (small, well-scoped):

- Fix clearly scoped bugs in `src/gdbplugin/sos/*.py` with tests.
- Add or tune tracing categories in `tracing.py` (default-suppress noisy cats; enable via `sostrace`).
- Improve architecture detection, DT_CONTEXT population, and disassembly steps for supported arches (x64, arm64).
- Reliability work around managed hosting initialization (bridge co-location, `InitManagedHosting`, `UpdateManagedTarget`).
- Test harness improvements in `src/tests/gdb/`.
- Documentation updates and developer ergonomics.

Use extra caution or seek human approval for:

- Changes in `src/diagnostics/` or `src/runtime/` (mirrors upstream repos).
- Public behavior changes, protocol changes, or broad refactors.
- Any change affecting release packaging or CI workflows.

Avoid without explicit approval:

- Introducing new external services/libraries that require secrets.
- Wide reformatting or unrelated cosmetic churn.

## How to build and test

- Build native components and publish artifacts:
  - Run `./build.sh` at repo root. Use `-c Debug|Release` as needed. (Agents should prefer `Release` for tests unless otherwise specified.)
- Run GDB-based tests:
  - Script: `src/tests/gdb/test.sh`
  - Environment knobs:
    - `GDB_BIN` (default: `gdb`)
    - `CONFIG` (`Debug` or `Release`)
    - `PLUGIN_PATH` (path to `sos.py`; if unset, script auto-detects under `artifacts/bin/`)
    - `HOST_BIN` (path to `dotnet`, default auto-detected)
    - `ASSEMBLY` (path to TestDebuggee.dll; auto-detected if available)
    - `SOS_ROOT` (defaults to `src/diagnostics/artifacts/bin/linux.<arch>.Release`)
    - `DOTNET_EnableWriteXorExecute` (tests default to `0`)
- Quick developer run (manual):
  - Load `sos.py` in GDB and interact with SOS commands (e.g., `clrstack`, `dso`, `clru`).

## Tracing and diagnostics

- Tracing is off by default. Enable selectively:
  - `sostrace on [cats]` — enable; optional include list
  - `sostrace off [cats]` — disable or exclude categories
  - `sostrace allow <cats>` — remove from exclude list
  - Useful cats: `bpmd`, `arch`, `disasm`, `help`, `read`, `write`, `output`, `interrupt`
- Noisy categories `read`, `output`, `interrupt` are excluded by default; allow explicitly if needed.

## Managed hosting (bridge) notes

- The native bridge (`libsosgdbbridge.so`) should be co-located with `libsos.so` for reliable hosting.
- SOS is initialized with a native `IHost*` via `SOSInitializeByHost`.
- Hosting is typically initialized via `InitManagedHosting`, and the target PID is propagated via `UpdateManagedTarget(pid)`.
- Eager hosting is acceptable so long as `UpdateManagedTarget` runs before symbol-dependent commands.

## Release workflow

- Creating an annotated tag matching `v*` (e.g., `v0.1.1`) on `main` triggers the build/upload release workflow.
- Example (maintainer only):
  - `git tag -a vX.Y.Z -m "gdbsos vX.Y.Z: summary"`
  - `git push origin vX.Y.Z`

## Coding conventions

- Keep changes minimal and focused; avoid reformatting unrelated code.
- Preserve existing public interfaces and behavior unless required by the task.
- Prefer small, reversible changes with clear tests and docs.
- Document environment gates for new behavior (e.g., `SOS_*` env vars).

## Security and privacy

- Do not commit secrets or credentials. Use environment variables when configuring symbol servers or diagnostics.
- Network access should be minimal and explicit; tests should run offline where possible.
- Respect the repository’s `CODE-OF-CONDUCT.md` and `SECURITY.md` (if present).

## PR expectations for agents

- Include a concise summary of the problem, the approach, and any risks.
- Add or update tests for user-visible behavior when practical.
- Provide brief run instructions and logs for validation (trim noisy logs).
- Pass basic gates locally (build, tests) before opening a PR.

## Contacts / ownership

- Primary code: `src/gdbplugin/sos/*` (Python) and `src/gdbplugin/bridge/*` (native)
- Maintainers: See repository owners and CODEOWNERS (if any).

---

If you are an automated agent, please follow the guidance above and limit changes to the smallest useful scope. When in doubt, open an issue or draft PR summarizing the proposed change and risks.
