gdbsos — GDB SOS plugin
[FAQ / Troubleshooting](docs/faq.md)
- src/gdbplugin/sos: Python plugin (GDB commands, services, ABI).
- src/gdbplugin/bridge: Native bridge (CMake + bridge.cpp).
- src/diagnostics: .NET diagnostics as a submodule.

Usage
- Build diagnostics, then build the bridge.
- Co-location required: libsosgdbbridge.so must be next to diagnostics' libsos.so.
- In GDB: source /path/to/src/diagnostics/artifacts/bin/current/sos.py to register commands.

Help and commands
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

Dev Container
- Reopen folder in container; submodules sync/init runs automatically.
- Manual build inside container:
	- ./build.sh -c Release

Deploy options
- Quick deploy for testing:
	- scripts/deploy-all.sh [-c Debug|Release] [-a arch] [-d <diagnostics bin dir>]
  Copies libsosgdbbridge.so next to diagnostics' libsos.so.
- Build-time deploy:
	- ./build.sh -c Release --deploy-to-diagnostics [--deploy-dir <path>]
  Passes -DBRIDGE_DEPLOY_TO_DIAGNOSTICS=ON (and optional target dir) to CMake.

For troubleshooting and FAQs, see `docs/faq.md`.
