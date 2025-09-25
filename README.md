gdbsos — GDB SOS plugin
[FAQ / Troubleshooting](docs/faq.md)
- src/gdbplugin/sos: Python plugin (GDB commands, services, ABI).
- src/gdbplugin/bridge: Native bridge (CMake + bridge.cpp).
- src/diagnostics: .NET diagnostics as a submodule.

Usage
- Build diagnostics, then build the bridge.
- libsos.so discovery: at runtime we search (in order): $SOS_ROOT/libsos.so, ~/.dotnet/sos/libsos.so, then the directory containing sos.py.
- Bridge co-location policy: regardless of where sos.py resides, when libsos.so is found in another directory we stage (copy if necessary) and always load libsosgdbbridge.so from the same directory as libsos.so. This is required for reliable managed hosting (prevents hosting delegate 0x80070002 failures). No override is provided to revert the legacy separated layout.
- In GDB: source /path/to/sos.py to register commands.

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
- Obsolete: historical deploy helpers that copied the bridge and Python files into the diagnostics artifacts/bin tree have been deprecated. The build no longer deploys to diagnostics; related CMake/script logic is commented out. Rely on SOS_ROOT or ~/.dotnet/sos for libsos.so; the runtime automatically co-locates the bridge with libsos when needed.

For troubleshooting and FAQs, see `docs/faq.md`.
