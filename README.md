gdbsos — GDB SOS plugin
- src/gdbplugin/sos: Python plugin (GDB commands, services, ABI).
- src/gdbplugin/bridge: Native bridge (CMake + bridge.cpp).
- src/diagnostics: .NET diagnostics as a submodule.
Usage
- Build diagnostics; set SOS_LIB_PATH and SOS_BRIDGE_LIB_PATH to artifacts.
- In GDB: source sos.py to register commands.
