gdbsos — GDB SOS plugin
- src/gdbplugin/sos: Python plugin (GDB commands, services, ABI).
- src/gdbplugin/bridge: Native bridge (CMake + bridge.cpp).
- src/diagnostics: .NET diagnostics as a submodule.
Usage
- Build diagnostics; set SOS_LIB_PATH and SOS_BRIDGE_LIB_PATH to artifacts.
- In GDB: source sos.py to register commands.

Dev Container
- Requires VS Code Dev Containers extension.
- Reopen folder in container; submodules sync/init runs automatically.
- Optional: set BUILD_BRIDGE=1 and CMAKE_BUILD_TYPE=RelWithDebInfo to build bridge on start.
- Default CMake generator: Ninja.
- Manual build inside container:
	- cmake -S src/gdbplugin/bridge -B build/bridge -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
	- cmake --build build/bridge --parallel
