import gdb
import ctypes
import os
import sys
import re
from typing import Optional

# Ensure this directory is absolute and on sys.path for sibling module imports
try:
    _THIS_DIR = os.path.dirname(os.path.realpath(__file__))
except Exception:
    _THIS_DIR = os.path.dirname(__file__)
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from abi import PVOID, PCSTR, HRESULT
from services import GdbServices
from tracing import TRACE_ENABLED, SOSTraceCommand

def _find_libsos() -> Optional[str]:
    """Locate libsos.so co-located with this script (same directory)."""
    p = os.path.join(_THIS_DIR, "libsos.so")
    return p if os.path.exists(p) else None

# Try to detect a suitable .NET runtime directory for hosting (directory containing libcoreclr.so)
## removed auto runtime detection for troubleshooting

# Common HRESULT hints for nicer error messages
_HRES_HINTS = {
    0x80070057: "Invalid argument. Check command options.",
    0x80004001: "Not implemented for this target.",
    0x80004002: "Interface not supported (service unavailable).",
    0x80004003: "Invalid pointer (internal).",
    0x80004005: "Unspecified failure. Try 'sostrace on' for details.",
    0x8007000E: "Out of memory.",
    0x80070005: "Access denied or memory read failed.",
    0x800704C7: "Operation canceled.",
}

# Manual mapping of command name -> libsos export symbol to align with LLDB registrations
MANUAL_EXPORTS = {
    # Native-style commands
    "clrstack": "ClrStack",
    "clrthreads": "Threads",
    "clru": "u",
    "dbgout": "dbgout",
    "dumpalc": "DumpALC",
    "dumparray": "DumpArray",
    "dumpassembly": "DumpAssembly",
    "dumpclass": "DumpClass",
    "dumpdelegate": "DumpDelegate",
    "dumpdomain": "DumpDomain",
    "dumpgcdata": "DumpGCData",
    "dumpil": "DumpIL",
    "dumplog": "DumpLog",
    "dumpmd": "DumpMD",
    "dumpmodule": "DumpModule",
    "dumpmt": "DumpMT",
    "dumpobj": "DumpObj",
    "dumpsig": "DumpSig",
    "dumpsigelem": "DumpSigElem",
    "dumpstack": "DumpStack",
    "dumpvc": "DumpVC",
    "eestack": "EEStack",
    "eeversion": "EEVersion",
    "ehinfo": "EHInfo",
    "findappdomain": "FindAppDomain",
    "findroots": "FindRoots",
    "gchandles": "GCHandles",
    "gcinfo": "GCInfo",
    "histclear": "HistClear",
    "histinit": "HistInit",
    "histobj": "HistObj",
    "histobjfind": "HistObjFind",
    "histroot": "HistRoot",
    "histstats": "HistStats",
    "ip2md": "IP2MD",
    "name2ee": "Name2EE",
    "pe": "PrintException",
    "printexception": "PrintException",
    "runtimes": "runtimes",
    "stoponcatch": "StopOnCatch",
    "setclrpath": "SetClrPath",
    "soshelp": "Help",
    "sosstatus": "SOSStatus",
    "sosflush": "SOSFlush",
    "syncblk": "SyncBlk",
    "threadstate": "ThreadState",
    "token2ee": "token2ee",
    # Common managed/also-exported
    "dumpheap": "DumpHeap",
    "gcroot": "GcRoot",
    "gcwhere": "GcWhere",
    "listnearobj": "ListNearObj",
    "loadsymbols": "LoadSymbols",
    "logging": "Logging",
    "objsize": "ObjSize",
    "pathto": "PathTo",
    "setsymbolserver": "SetSymbolServer",
    "threadpool": "ThreadPool",
    "verifyheap": "VerifyHeap",
    "verifyobj": "VerifyObj",
    "traverseheap": "TraverseHeap",
    # Aliases and special
    "dso": "DumpStackObjects",
    "dumpstackobjects": "DumpStackObjects",
}

def _to_export_candidates_common(cmd: str):
    """Build a list of plausible export names for a given SOS command name."""
    cmd = (cmd or "").strip()
    candidates = []
    m = MANUAL_EXPORTS.get(cmd)
    if m:
        candidates.append(m)
    # Title-case from separators (e.g., dump-heap -> DumpHeap)
    title = ''.join(part.capitalize() for part in re.split(r'[^0-9A-Za-z]+', cmd) if part)
    if title and title not in candidates:
        candidates.append(title)
    cap = cmd.capitalize()
    if cap not in candidates:
        candidates.append(cap)
    if cmd and cmd not in candidates:
        candidates.append(cmd)
    return candidates

# Commands that require IMemoryRegionService/NativeAddressHelper and are only
# supported under WinDbg/cdb today. Provide a friendlier message in GDB.
_UNSUPPORTED_WINDBG_ONLY = {
    "gctonative",
    "findpointersin",
    "maddress",
}

def _hint_for_hresult(hr: int) -> str:
    try:
        h = hr & 0xFFFFFFFF
    except Exception:
        h = hr
    return _HRES_HINTS.get(h, "")


class SOSCommand(gdb.Command):
    """A base class for SOS commands that handles loading libsos."""
    def __init__(self, name):
        super(SOSCommand, self).__init__(name, gdb.COMMAND_DATA)
        self.name = name
        SOSCommand.lazy_load_sos()

    # Track whether managed hosting was successfully initialized in this session
    hosting_initialized: bool = False

    @staticmethod
    def _is_runtime_loaded() -> bool:
        try:
            # Use our services helper to detect libcoreclr.so in the target maps
            if not hasattr(SOSCommand, 'gdb_services') or SOSCommand.gdb_services is None:
                return False
            path, base = SOSCommand.gdb_services._scan_coreclr()
            return bool(path and base is not None)
        except Exception:
            return False

    @staticmethod
    def _try_initialize_hosting_if_needed() -> bool:
        """Initialize managed hosting once the target CLR is loaded. Returns True if ready."""
        # Already initialized
        if getattr(SOSCommand, 'hosting_initialized', False):
            return True
        # Only attempt when CLR is loaded in the target
        if not SOSCommand._is_runtime_loaded():
            # Defer with a clear message
            gdb.write("Target .NET runtime isn't loaded yet; managed SOS commands will be available after CLR loads.\n")
            return False
        # Attempt to initialize via libsos forwarder first, then bridge
        try:
            hres = None
            if getattr(SOSCommand, 'sos_init_hosting', None):
                hres = SOSCommand.sos_init_hosting(None, 0)
            elif getattr(SOSCommand, 'bridge_handle', None):
                init_hosting = getattr(SOSCommand.bridge_handle, 'InitManagedHosting', None)
                if init_hosting is not None:
                    init_hosting.argtypes = [ctypes.c_char_p, ctypes.c_int]
                    init_hosting.restype = ctypes.c_int
                    hres = init_hosting(None, 0)
            if hres == 0:
                SOSCommand.hosting_initialized = True
                gdb.write("Managed hosting initialized.\n")
                return True
            if hres is not None:
                h32 = hres & 0xFFFFFFFF
                hint = _hint_for_hresult(h32)
                if hint:
                    gdb.write(f"InitManagedHosting failed (HRESULT=0x{h32:08x}). {hint}\n")
                else:
                    gdb.write(f"InitManagedHosting failed (HRESULT=0x{h32:08x}).\n")
        except Exception as e:
            gdb.write(f"Error initializing hosting: {e}\n")
        return False

    @staticmethod
    def lazy_load_sos():
        """Loads and initializes libsos.so if not already loaded."""
        if not hasattr(SOSCommand, "sos_handle"):
            SOSCommand.sos_handle = None
        if SOSCommand.sos_handle:
            return True

        try:
            # Load the bridge first from the same directory as this script
            if TRACE_ENABLED:
                gdb.write("[sos] Probing for libsosgdbbridge.so...\n")
            _dl_mode = getattr(ctypes, 'RTLD_GLOBAL', None)
            SOSCommand.bridge_handle = None
            try:
                local_bridge = os.path.join(_THIS_DIR, "libsosgdbbridge.so")
                if os.path.exists(local_bridge):
                    if TRACE_ENABLED:
                        gdb.write(f"[sos] Loading bridge from '{local_bridge}'...\n")
                    SOSCommand.bridge_handle = ctypes.CDLL(local_bridge, mode=_dl_mode) if _dl_mode is not None else ctypes.CDLL(local_bridge)
            except Exception as e:
                SOSCommand.bridge_handle = None
                if TRACE_ENABLED:
                    gdb.write(f"[sos] Bridge load note: {e}\n")

            # Discover libsos strictly co-located with this script
            libsos_path = _find_libsos()
            if not libsos_path:
                gdb.write("Error: Unable to locate libsos.so.\n")
                gdb.write("Hint: copy libsos.so next to sos.py (diagnostics/artifacts/bin/current).\n")
                return False

            if TRACE_ENABLED:
                gdb.write(f"[sos] Loading libsos from '{libsos_path}'...\n")
            SOSCommand.sos_handle = ctypes.CDLL(libsos_path, mode=_dl_mode) if _dl_mode is not None else ctypes.CDLL(libsos_path)

            if TRACE_ENABLED:
                gdb.write("[sos] Creating GdbServices...\n")
            SOSCommand.gdb_services = GdbServices()
            # Optional libsos forwarders
            try:
                SOSCommand.sos_init_hosting = SOSCommand.sos_handle.SOS_InitManagedHosting
                SOSCommand.sos_init_hosting.argtypes = [ctypes.c_char_p, ctypes.c_int]
                SOSCommand.sos_init_hosting.restype = ctypes.c_int
            except Exception:
                SOSCommand.sos_init_hosting = None
            try:
                SOSCommand.sos_dispatch_managed = SOSCommand.sos_handle.SOS_DispatchManagedCommand
                SOSCommand.sos_dispatch_managed.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                SOSCommand.sos_dispatch_managed.restype = ctypes.c_int
            except Exception:
                SOSCommand.sos_dispatch_managed = None

            # Initialize the SOS library
            if TRACE_ENABLED:
                gdb.write("[sos] Resolving SOSInitializeByHost...\n")
            init_func = SOSCommand.sos_handle.SOSInitializeByHost
            if TRACE_ENABLED:
                gdb.write("[sos] Calling SOSInitializeByHost(NULL, IDebuggerServices) ...\n")

            # SOSInitializeByHost(IUnknown* punk, IDebuggerServices* debuggerServices)
            init_func.argtypes = [PVOID, PVOID]
            init_func.restype = HRESULT

            hr = init_func(ctypes.c_void_p(0), ctypes.byref(SOSCommand.gdb_services.idebugger_ptr))

            if hr != 0:
                gdb.write(f"SOSInitializeByHost failed with HRESULT {hr}.\n")
                SOSCommand.sos_handle = None
                return False

            # Initialize the bridge's Extensions singleton now; defer managed hosting
            try:
                if getattr(SOSCommand, 'bridge_handle', None):
                    # Initialize the bridge's Extensions singleton first
                    init_ext = getattr(SOSCommand.bridge_handle, 'InitGdbExtensions', None)
                    if init_ext is not None:
                        init_ext.argtypes = [ctypes.c_void_p]
                        init_ext.restype = ctypes.c_int
                        idebugger_ptr_addr = ctypes.addressof(SOSCommand.gdb_services.idebugger_ptr)
                        init_ext(ctypes.c_void_p(idebugger_ptr_addr))
                # Do not call InitManagedHosting here to avoid early managed assertion before target state is ready
            except Exception as e:
                if TRACE_ENABLED:
                    gdb.write(f"[sos] Bridge InitGdbExtensions note: {e}\n")

            gdb.write("SOS GDB Python extension loaded and initialized successfully.\n")
            return True
        except Exception as e:
            gdb.write(f"Error loading or initializing libsos.so: {e}\n")
            SOSCommand.sos_handle = None
            return False

    def invoke(self, arg, from_tty):
        if not SOSCommand.lazy_load_sos():
            return

        try:
            # Prefer native exports first to avoid managed noise like "Unrecognized SOS command".
            # Resolve the exported SOS symbol for this command

            sos_func = None
            tried = []
            for sym in _to_export_candidates_common(self.name.lower()):
                tried.append(sym)
                try:
                    sos_func = getattr(SOSCommand.sos_handle, sym)
                    break
                except AttributeError:
                    continue
            if sos_func is not None:
                sos_func.argtypes = [PVOID, PCSTR]
                sos_func.restype = HRESULT

                client_ptr = ctypes.byref(SOSCommand.gdb_services.illldb_ptr)
                if TRACE_ENABLED:
                    gdb.write("[sos] Dispatching SOS command with ILLDBServices client\n")
                hr = sos_func(client_ptr, (arg or "").encode('utf-8'))
                if hr != 0:
                    gdb.write(f"Command '{self.name}' failed with HRESULT {hr}.\n")
                return

            # Native export not found; try managed dispatch next
            cmd = self.name.lower().encode('utf-8')
            args = (arg or "").encode('utf-8')
            bridge = getattr(SOSCommand, 'bridge_handle', None)
            hres_bridge = None
            hosting_initialized = False
            # Ensure hosting is initialized only when CLR is present, mirroring LLDB behavior
            if not SOSCommand._try_initialize_hosting_if_needed():
                return
            if bridge is not None:
                try:
                    dispatch = bridge.DispatchManagedCommand
                    dispatch.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                    dispatch.restype = ctypes.c_int
                    hres_bridge = dispatch(cmd, args)
                    if TRACE_ENABLED:
                        gdb.write(f"[sos] Bridge DispatchManagedCommand('{self.name}') => 0x{hres_bridge:08x}\n")
                    if hres_bridge == 0:
                        return
                    # Check hosting status if bridge is present
                    try:
                        get_host = getattr(bridge, 'GetHostForSos', None)
                        if get_host is not None:
                            get_host.argtypes = []
                            get_host.restype = ctypes.c_void_p
                            hosting_initialized = bool(get_host())
                    except Exception:
                        pass
                except Exception:
                    pass
            # Try libsos forwarder as a fallback
            hres_forwarder = None
            try:
                # Attempt forwarder only after trying bridge
                if getattr(SOSCommand, 'sos_dispatch_managed', None):
                    hres_forwarder = SOSCommand.sos_dispatch_managed(cmd, args)
                    if hres_forwarder == 0:
                        return
            except Exception:
                pass
            # Distinguish hosting-not-initialized vs command failure
            if hosting_initialized or (hres_bridge not in (None, 0)) or (hres_forwarder not in (None, 0)):
                h = hres_bridge if hres_bridge not in (None, 0) else (hres_forwarder if hres_forwarder not in (None, 0) else 0)
                if h:
                    h32 = h & 0xFFFFFFFF
                    hint = _hint_for_hresult(h32)
                    if hint:
                        gdb.write(f"Managed command '{self.name}' failed (HRESULT=0x{h32:08x}). {hint}\n")
                    else:
                        gdb.write(f"Managed command '{self.name}' failed (HRESULT=0x{h32:08x}).\n")
                return
            # If we never managed to dispatch, print guidance
            gdb.write(
                "This command is managed-only on Linux and isn’t exported from libsos.so.\n"
                "Managed hosting is not initialized or failed.\n"
                "Try: sethostruntime or use lldb’s sos plugin / dotnet-dump.\n"
            )

        except AttributeError:
            gdb.write(f"Error: Command '{self.name}' not found in libsos.so.\n")
        except Exception as e:
            gdb.write(f"An error occurred while executing '{self.name}': {e}\n")



class SosUmbrellaCommand(gdb.Command):
    """sos <command> [args] — Dispatch any SOS command without per-command wrappers."""
    def __init__(self):
        super(SosUmbrellaCommand, self).__init__("sos", gdb.COMMAND_DATA)

    def _to_export_candidates(self, cmd: str):
        return _to_export_candidates_common(cmd)

    def invoke(self, arg, from_tty):
        if not SOSCommand.lazy_load_sos():
            return
        parts = arg.strip().split(None, 1) if arg else []
        if not parts:
            gdb.write("Usage: sos <command> [args]\n")
            return
        name = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""

        # Friendly notice for WinDbg/cdb-only commands
        if name in _UNSUPPORTED_WINDBG_ONLY:
            gdb.write("This command is only supported under windbg/cdb currently\n")
            return

        # 1) Try native export first to avoid managed-side warning output
        tried = []
        sos_func = None
        for sym in self._to_export_candidates(name):
            tried.append(sym)
            try:
                sos_func = getattr(SOSCommand.sos_handle, sym)
                break
            except AttributeError:
                continue
        if sos_func is not None:
            try:
                sos_func.argtypes = [PVOID, PCSTR]
                sos_func.restype = HRESULT
                client_ptr = ctypes.byref(SOSCommand.gdb_services.illldb_ptr)
                if TRACE_ENABLED:
                    gdb.write("[sos] Dispatching native SOS command via ILLDBServices client\n")
                hr = sos_func(client_ptr, (rest or "").encode('utf-8'))
                if hr != 0:
                    gdb.write(f"Command '{name}' failed with HRESULT {hr}.\n")
                return
            except Exception as e:
                gdb.write(f"An error occurred while executing '{name}': {e}\n")
                return

    # 2) Fall back to managed dispatch via bridge/libsos forwarder
        cmd = name.encode('utf-8')
        args = rest.encode('utf-8')
        bridge = getattr(SOSCommand, 'bridge_handle', None)
        hres_bridge = None
        # Initialize hosting lazily only when the CLR is loaded
        if not SOSCommand._try_initialize_hosting_if_needed():
            return
        try:
            if bridge is not None:
                dispatch = bridge.DispatchManagedCommand
                dispatch.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                dispatch.restype = ctypes.c_int
                hres_bridge = dispatch(cmd, args)
                if TRACE_ENABLED:
                    gdb.write(f"[sos] Bridge DispatchManagedCommand('{name}') => 0x{hres_bridge:08x}\n")
                if hres_bridge == 0:
                    return
        except Exception:
            pass
        try:
            if getattr(SOSCommand, 'sos_dispatch_managed', None):
                hres = SOSCommand.sos_dispatch_managed(cmd, args)
                if hres == 0:
                    return
        except Exception:
            pass
        gdb.write(f"Error: Command '{name}' not found (tried symbols: {', '.join(tried)}).\n")


SosUmbrellaCommand()


class ExtUmbrellaCommand(gdb.Command):
    """ext <command> [args] — Alias for 'sos' umbrella."""
    def __init__(self):
        super(ExtUmbrellaCommand, self).__init__("ext", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        gdb.execute(f"sos {arg}")


ExtUmbrellaCommand()

SOSTraceCommand()


class SetHostRuntimeCommand(gdb.Command):
    """Initialize SOS managed hosting. Usage: sethostruntime [-major N] [<runtime-directory>]"""
    def __init__(self):
        super(SetHostRuntimeCommand, self).__init__("sethostruntime", gdb.COMMAND_SUPPORT)

    def invoke(self, arg, from_tty):
    # Prefer libsos forwarder; fall back to bridge
        parts = arg.split() if arg else []
        major = 0
        runtime_dir = None
        i = 0
        while i < len(parts):
            if parts[i] == '-major' and i + 1 < len(parts):
                try:
                    major = int(parts[i + 1], 10)
                except Exception:
                    major = 0
                i += 2
            else:
                runtime_dir = parts[i]
                i += 1
        try:
            hres = None
            if getattr(SOSCommand, 'sos_init_hosting', None):
                hres = SOSCommand.sos_init_hosting(runtime_dir.encode('utf-8') if runtime_dir else None, int(major))
            elif getattr(SOSCommand, 'bridge_handle', None):
                init_hosting = SOSCommand.bridge_handle.InitManagedHosting
                init_hosting.argtypes = [ctypes.c_char_p, ctypes.c_int]
                init_hosting.restype = ctypes.c_int
                hres = init_hosting(runtime_dir.encode('utf-8') if runtime_dir else None, int(major))
            else:
                gdb.write("No hosting initializer available (libsos forwarder and bridge not found).\n")
                return
            if hres == 0:
                gdb.write("Managed hosting initialized.\n")
            else:
                gdb.write(f"InitManagedHosting failed HRESULT=0x{hres:08x}.\n")
        except Exception as e:
            gdb.write(f"Error initializing hosting: {e}\n")


SetHostRuntimeCommand()


# Register the same command set LLDB does for parity and direct use without 'sos' prefix
def _register_default_commands():
    names = [
        # Native exports
    "clrstack", "clrthreads", "clru", "dbgout", "bpmd", "dumpalc", "dumparray", "dumpassembly",
        "dumpclass", "dumpdelegate", "dumpdomain", "dumpgcdata", "dumpil", "dumplog", "dumpmd",
        "dumpmodule", "dumpmt", "dumpobj", "dumpsig", "dumpsigelem", "dumpstack", "dumpvc",
        "eestack", "eeversion", "ehinfo", "findappdomain", "findroots", "gchandles", "gcinfo",
        "histclear", "histinit", "histobj", "histobjfind", "histroot", "histstats", "ip2md",
        "name2ee", "pe", "printexception", "runtimes", "stoponcatch", "setclrpath", "soshelp",
        "sosstatus", "sosflush", "syncblk", "threadstate", "token2ee",
        # Managed or both
    "analyzeoom", "assemblies", "clrmodules", "crashinfo", "dumpasync", "dumpheap", "dumphttp",
        "dumpruntimetypes", "dumprequests", "dumpstackobjects", "dso", "eeheap", "gcroot",
        "gcwhere", "listnearobj", "loadsymbols", "logging", "objsize", "pathto", "setsymbolserver",
        "threadpool", "verifyheap", "verifyobj", "traverseheap", "gcheapstat", "finalizequeue",
    ]
    for n in names:
        try:
            SOSCommand(n)
        except Exception:
            pass


_register_default_commands()


# Register stubs for WinDbg/cdb-only commands so direct invocation prints a clear message.
class UnsupportedSosCommand(gdb.Command):
    def __init__(self, name: str):
        super(UnsupportedSosCommand, self).__init__(name, gdb.COMMAND_SUPPORT)
        self._name = name

    def invoke(self, arg, from_tty):
        gdb.write("This command is only supported under windbg/cdb currently\n")


for _n in sorted(_UNSUPPORTED_WINDBG_ONLY):
    try:
        UnsupportedSosCommand(_n)
    except Exception:
        pass
