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
    """Per-command SOS wrapper that loads libsos and dispatches native/managed handlers."""
    def __init__(self, name, helptext: Optional[str] = None):
        # name may be either a top-level command (e.g., "dumpheap") or a subcommand (e.g., "sos dumpheap")
        super(SOSCommand, self).__init__(name, gdb.COMMAND_DATA)
        self.name = name
        # Note: GDB's help system reads the class docstring, not instance doc, for command help.
        # We create dynamic subclasses with per-command class __doc__ at registration time.
        if helptext:
            # Keep as a fallback in case some GDB versions consult instance-level __doc__
            self.__doc__ = helptext
    # Defer libsos/SOS initialization until a command is actually invoked
    # (align with LLDB plugin behavior). We'll load on-demand in invoke().

    # Track whether managed hosting was successfully initialized in this session
    hosting_initialized: bool = False
    # Track runtime load transition to auto-flush SOS caches once
    _runtime_loaded_last: bool = False
    _post_load_flushed: bool = False

    @staticmethod
    def _call_sosflush_if_available():
        try:
            if not getattr(SOSCommand, 'sos_handle', None):
                return False
            # Resolve SOSFlush export (native) and invoke it with ILLDBServices
            func = None
            for sym in _to_export_candidates_common('sosflush'):
                try:
                    func = getattr(SOSCommand.sos_handle, sym)
                    break
                except AttributeError:
                    continue
            if not func:
                return False
            func.argtypes = [PVOID, PCSTR]
            func.restype = HRESULT
            client_ptr = ctypes.byref(SOSCommand.gdb_services.illldb_ptr) if getattr(SOSCommand, 'gdb_services', None) else PVOID()
            hr = func(client_ptr, b"")
            return hr == 0
        except Exception:
            return False

    @staticmethod
    def _maybe_flush_after_runtime_load():
        """If the target CLR has just loaded after earlier failures, flush SOS caches."""
        try:
            now_loaded = SOSCommand._is_runtime_loaded()
            if now_loaded and not SOSCommand._runtime_loaded_last and not SOSCommand._post_load_flushed:
                # Try flushing once to clear any stale "no runtime" error state inside SOS
                SOSCommand._call_sosflush_if_available()
                # Also notify the managed host of the current PID so it can create/update the target.
                try:
                    pid = 0
                    if hasattr(SOSCommand, 'gdb_services') and SOSCommand.gdb_services is not None:
                        pid = SOSCommand.gdb_services._get_pid() or 0
                    bridge = getattr(SOSCommand, 'bridge_handle', None)
                    if bridge is not None and pid:
                        upd = getattr(bridge, 'UpdateManagedTarget', None)
                        if upd is not None:
                            upd.argtypes = [ctypes.c_uint]
                            upd.restype = ctypes.c_int
                            hr = upd(int(pid))
                            if TRACE_ENABLED:
                                gdb.write(f"[sos] UpdateManagedTarget(pid={pid}) => 0x{hr & 0xFFFFFFFF:08x}\n")
                except Exception as ex:
                    if TRACE_ENABLED:
                        gdb.write(f"[sos] UpdateManagedTarget note: {ex}\n")
                SOSCommand._post_load_flushed = True
            SOSCommand._runtime_loaded_last = now_loaded
        except Exception:
            pass

    # (Removed) Python-layer bpmd pending queue, runtime entry breakpoint planting,
    # and defer hooks. Native SOS host is responsible for pending managed breakpoints
    # via runtime-loaded and code-gen notifications (LLDB parity).

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
                # After hosting init, ensure managed target is updated with current PID
                try:
                    pid = 0
                    if hasattr(SOSCommand, 'gdb_services') and SOSCommand.gdb_services is not None:
                        pid = SOSCommand.gdb_services._get_pid() or 0
                    bridge = getattr(SOSCommand, 'bridge_handle', None)
                    if bridge is not None and pid:
                        upd = getattr(bridge, 'UpdateManagedTarget', None)
                        if upd is not None:
                            upd.argtypes = [ctypes.c_uint]
                            upd.restype = ctypes.c_int
                            hr2 = upd(int(pid))
                            if TRACE_ENABLED:
                                gdb.write(f"[sos] UpdateManagedTarget(pid={pid}) => 0x{hr2 & 0xFFFFFFFF:08x}\n")
                except Exception as ex:
                    if TRACE_ENABLED:
                        gdb.write(f"[sos] UpdateManagedTarget note: {ex}\n")
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

            # Initialize the bridge's Extensions singleton BEFORE calling SOSInitializeByHost,
            # so we can retrieve the native IHost* and pass it to SOS (align with LLDB).
            try:
                if getattr(SOSCommand, 'bridge_handle', None):
                    init_ext = getattr(SOSCommand.bridge_handle, 'InitGdbExtensions', None)
                    if init_ext is not None:
                        init_ext.argtypes = [ctypes.c_void_p]
                        init_ext.restype = ctypes.c_int
                        idebugger_ptr_addr = ctypes.addressof(SOSCommand.gdb_services.idebugger_ptr)
                        init_ext(ctypes.c_void_p(idebugger_ptr_addr))
                    # Wire UpdateManagedTarget into services for proactive PID update calls
                    try:
                        upd = getattr(SOSCommand.bridge_handle, 'UpdateManagedTarget', None)
                        if upd is not None:
                            upd.argtypes = [ctypes.c_uint]
                            upd.restype = ctypes.c_int
                            # Assign a small wrapper to services so it can invoke the bridge
                            def _bridge_update(pid: int):
                                try:
                                    return upd(int(pid))
                                except Exception:
                                    return 0x80004005
                            try:
                                # services module class has attribute for this
                                SOSCommand.gdb_services._bridge_update_fn = _bridge_update
                            except Exception:
                                pass
                    except Exception as exu:
                        if TRACE_ENABLED:
                            gdb.write(f"[sos] bridge UpdateManagedTarget wiring note: {exu}\n")
            except Exception as e:
                if TRACE_ENABLED:
                    gdb.write(f"[sos] Bridge InitGdbExtensions note: {e}\n")

            # Resolve the native host pointer from the bridge if enabled
            native_host_ptr = None
            try:
                if getattr(SOSCommand, 'bridge_handle', None):
                    get_host = getattr(SOSCommand.bridge_handle, 'GetHostForSos', None)
                    if get_host is not None:
                        get_host.argtypes = []
                        get_host.restype = ctypes.c_void_p
                        native_host_ptr = get_host()
                        if TRACE_ENABLED and native_host_ptr:
                            gdb.write(f"[sos] Native IHost from bridge: 0x{native_host_ptr:x}\n")
            except Exception as e:
                if TRACE_ENABLED:
                    gdb.write(f"[sos] GetHostForSos note: {e}\n")

            # Initialize the SOS library
            if TRACE_ENABLED:
                gdb.write("[sos] Resolving SOSInitializeByHost...\n")
            init_func = SOSCommand.sos_handle.SOSInitializeByHost
            init_func.argtypes = [PVOID, PVOID]
            init_func.restype = HRESULT

            # Prefer native host from bridge by default; allow override via env.
            # We no longer fabricate a Python host fallback to avoid creating a 2nd host/runtime.
            use_host = os.environ.get('SOS_GDB_USE_HOST', '1') not in ('', '0', 'false', 'False')
            if use_host and not native_host_ptr and getattr(SOSCommand, 'bridge_handle', None):
                # Do NOT start managed hosting until the target CLR is actually loaded.
                # This prevents pre-run help from trying to use managed plumbing and failing.
                if SOSCommand._is_runtime_loaded():
                    try:
                        init_managed = getattr(SOSCommand.bridge_handle, 'InitManagedHosting', None)
                        if init_managed is not None:
                            init_managed.argtypes = [ctypes.c_char_p, ctypes.c_int]
                            init_managed.restype = ctypes.c_int
                            hr_host = init_managed(None, 0)
                            if TRACE_ENABLED:
                                gdb.write(f"[sos] InitManagedHosting retry hr=0x{hr_host & 0xFFFFFFFF:08x}\n")
                            # Requery host pointer after attempt
                            try:
                                get_host = getattr(SOSCommand.bridge_handle, 'GetHostForSos', None)
                                if get_host is not None:
                                    get_host.argtypes = []
                                    get_host.restype = ctypes.c_void_p
                                    native_host_ptr = get_host()
                                    if TRACE_ENABLED and native_host_ptr:
                                        gdb.write(f"[sos] Native IHost acquired after retry: 0x{native_host_ptr:x}\n")
                            except Exception as ex2:
                                if TRACE_ENABLED:
                                    gdb.write(f"[sos] Host requery note: {ex2}\n")
                    except Exception as ex1:
                        if TRACE_ENABLED:
                            gdb.write(f"[sos] InitManagedHosting retry exception: {ex1}\n")

            if use_host:
                if native_host_ptr:
                    host_arg = ctypes.c_void_p(native_host_ptr)
                    if TRACE_ENABLED:
                        gdb.write(f"[sos] Calling SOSInitializeByHost(native host, IDebuggerServices=0x{ctypes.addressof(SOSCommand.gdb_services.idebugger_ptr):x}) ...\n")
                else:
                    # Do not fallback to Python host; proceed with NULL to surface issue & avoid duplicate host.
                    host_arg = None
                    gdb.write("[sos][warn] Native host not available; proceeding with NULL host (no Python fallback).\n")
                    if TRACE_ENABLED:
                        gdb.write(f"[sos] Calling SOSInitializeByHost(NULL host, IDebuggerServices=0x{ctypes.addressof(SOSCommand.gdb_services.idebugger_ptr):x}) ...\n")
            else:
                host_arg = None
                if TRACE_ENABLED:
                    gdb.write(f"[sos] Calling SOSInitializeByHost(NULL host, IDebuggerServices=0x{ctypes.addressof(SOSCommand.gdb_services.idebugger_ptr):x}) ...\n")

            hr = init_func(host_arg, ctypes.byref(SOSCommand.gdb_services.idebugger_ptr))

            if hr != 0:
                gdb.write(f"SOSInitializeByHost failed with HRESULT {hr}.\n")
                SOSCommand.sos_handle = None
                return False

            if use_host:
                if native_host_ptr:
                    gdb.write("SOS GDB Python extension loaded (native host).\n")
                else:
                    gdb.write("SOS GDB Python extension loaded (NO native host; NULL host path).\n")
            else:
                gdb.write("SOS GDB Python extension loaded (host disabled via env).\n")
            return True
        except Exception as e:
            gdb.write(f"Error loading or initializing libsos.so: {e}\n")
            SOSCommand.sos_handle = None
            return False

    def invoke(self, arg, from_tty):
        if not SOSCommand.lazy_load_sos():
            return

        try:
            # Clear any prior user-interrupt state at the beginning of a command
            try:
                if hasattr(SOSCommand, 'gdb_services') and SOSCommand.gdb_services is not None:
                    SOSCommand.gdb_services.clear_interrupt()
            except Exception:
                pass
            # If CLR just became available after earlier failures, clear stale error state once
            SOSCommand._maybe_flush_after_runtime_load()
            # Determine the logical SOS command name (last token to support 'sos <cmd>')
            try:
                lower_name = (self.name or "").split()[-1].lower()
            except Exception:
                lower_name = (self.name or "").lower()
            # For help/soshelp, prefer managed help when CLR is loaded for richer output
            # LLDB-aligned: deliver bpmd immediately even if CLR not loaded
            # (libsos native export path will set runtime callbacks/pending bp if supported).
            # No pre-CLR queuing or local pending bp planting here.
            # We simply fall through to dispatch below.
            if lower_name in ("help", "soshelp"):
                # Special-case behavior for LLDB parity:
                # - 'help' should NOT initialize hosting; show managed help only if runtime already loaded
                # - 'soshelp' SHOULD attempt to initialize hosting and show managed help; else fallback to static
                if lower_name == "soshelp":
                    # 0) Prefer native Help export first; it may print a partial list and/or try to initialize hosting
                    try:
                        sos_help = getattr(SOSCommand.sos_handle, "Help")
                        sos_help.argtypes = [PVOID, PCSTR]
                        sos_help.restype = HRESULT
                        client_ptr = ctypes.byref(SOSCommand.gdb_services.illldb_ptr)
                        hrh = sos_help(client_ptr, (arg or "").encode('utf-8'))
                        if hrh == 0:
                            return
                    except Exception:
                        pass
                    # 1) Attempt relaxed hosting init regardless of runtime load state
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
                        # ignore hres; proceed to managed help attempt regardless
                    except Exception:
                        pass
                    # 2) Try managed 'help'
                    try:
                        bridge = getattr(SOSCommand, 'bridge_handle', None)
                        if bridge is not None:
                            dispatch = bridge.DispatchManagedCommand
                            dispatch.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                            dispatch.restype = ctypes.c_int
                            if dispatch(b"help", (arg or "").encode('utf-8')) == 0:
                                return
                    except Exception:
                        pass
                    try:
                        if getattr(SOSCommand, 'sos_dispatch_managed', None):
                            if SOSCommand.sos_dispatch_managed(b"help", (arg or "").encode('utf-8')) == 0:
                                return
                    except Exception:
                        pass
                    # 3) Static fallback
                    _print_sos_help_static(arg)
                    return
                else:
                    # 'help' command: do not initialize hosting, but use managed if runtime is ready
                    if SOSCommand._is_runtime_loaded() and SOSCommand._try_initialize_hosting_if_needed():
                        try:
                            bridge = getattr(SOSCommand, 'bridge_handle', None)
                            if bridge is not None:
                                dispatch = bridge.DispatchManagedCommand
                                dispatch.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                                dispatch.restype = ctypes.c_int
                                if dispatch(b"help", (arg or "").encode('utf-8')) == 0:
                                    return
                        except Exception:
                            pass
                        try:
                            if getattr(SOSCommand, 'sos_dispatch_managed', None):
                                if SOSCommand.sos_dispatch_managed(b"help", (arg or "").encode('utf-8')) == 0:
                                    return
                        except Exception:
                            pass
                    # Static help if runtime isn't ready
                    _print_sos_help_static(arg)
                    return

            # Prefer native exports first to avoid managed noise like "Unrecognized SOS command".
            # Resolve the exported SOS symbol for this command

            sos_func = None
            tried = []
            for sym in _to_export_candidates_common(lower_name):
                tried.append(sym)
                try:
                    sos_func = getattr(SOSCommand.sos_handle, sym)
                    break
                except AttributeError:
                    continue
            if sos_func is not None:
                # bpmd: no Python pending logic; native command sets up callbacks.
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
            cmd = lower_name.encode('utf-8')
            args = (arg or "").encode('utf-8')
            bridge = getattr(SOSCommand, 'bridge_handle', None)
            hres_bridge = None
            hosting_initialized = False
            # Ensure hosting is initialized only when CLR is present, mirroring LLDB behavior
            if not SOSCommand._is_runtime_loaded():
                # No CLR yet: provide a friendly message for managed-only commands
                if lower_name in ("help", "soshelp"):
                    gdb.write("SOS help is limited until the .NET runtime is loaded. Use 'help sos' to list available commands.\n")
                else:
                    gdb.write("This command is managed-only and requires the .NET runtime to be loaded.\n")
                return
            if not SOSCommand._try_initialize_hosting_if_needed():
                gdb.write("Managed hosting is not initialized; try 'sethostruntime' after the CLR loads.\n")
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



class SosPrefixCommand(gdb.Command):
    """SOS diagnostics commands. Use 'sos <command>' or see 'help sos <command>'."""
    def __init__(self):
        # True prefix command so 'help sos' lists subcommands cleanly
        super(SosPrefixCommand, self).__init__("sos", gdb.COMMAND_DATA, prefix=True)
        self.__doc__ = "SOS diagnostics commands. Type 'help sos' to list subcommands."

    def invoke(self, arg, from_tty):
        # If called without a subcommand, show brief guidance
        gdb.write("Usage: sos <command> [args]. Try 'help sos' for a list of commands.\n")


# Unified list of commands we register (used for both registration and static help)
COMMAND_NAMES = [
    # Native exports
    "clrstack", "clrthreads", "clru", "dbgout", "bpmd", "dumpalc", "dumparray", "dumpassembly",
    "dumpclass", "dumpdelegate", "dumpdomain", "dumpgcdata", "dumpil", "dumplog", "dumpmd",
    "dumpmodule", "dumpmt", "dumpobj", "dumpsig", "dumpsigelem", "dumpstack", "dumpvc",
    "eestack", "eeversion", "ehinfo", "findappdomain", "findroots", "gchandles", "gcinfo",
    "histclear", "histinit", "histobj", "histobjfind", "histroot", "histstats", "ip2md",
    "name2ee", "pe", "printexception", "runtimes", "stoponcatch", "setclrpath", "soshelp",
    "sosstatus", "sosflush", "syncblk", "threadstate", "token2ee",
    # Managed or both
    "help", "analyzeoom", "assemblies", "clrmodules", "crashinfo", "dumpasync", "dumpheap", "dumphttp",
    "dumpruntimetypes", "dumprequests", "dumpstackobjects", "dso", "eeheap", "gcroot",
    "gcwhere", "listnearobj", "loadsymbols", "logging", "objsize", "pathto", "setsymbolserver",
    "threadpool", "verifyheap", "verifyobj", "traverseheap", "gcheapstat", "finalizequeue",
]


def _print_sos_help_static(arg: Optional[str]):
    """Print a static, LLDB-like soshelp listing before the CLR loads (or when hosting isn't ready)."""
    def line_for(cmd: str) -> str:
        desc = COMMAND_HELP.get(cmd)
        if not desc:
            # fall back to a generic description
            desc = f"Run SOS command '{cmd}'."
        return f"{cmd} -- {desc}\n"

    # Exact LLDB-style header lines and order for pre-run soshelp
    LLDB_STATIC_BLOCK = [
        "crashinfo                                 Displays the crash details that created the dump.",
        "d, readmemory <address>                   Dumps memory contents.",
        "da <address>                              Dumps memory as zero-terminated byte strings.",
        "db <address>                              Dumps memory as bytes.",
        "dc <address>                              Dumps memory as chars.",
        "dd <address>                              Dumps memory as dwords (uint).",
        "dp <address>                              Dumps memory as pointers.",
        "dq <address>                              Dumps memory as qwords (ulong).",
        "du <address>                              Dumps memory as zero-terminated char strings.",
        "dw <address>                              Dumps memory as words (ushort).",
        "help, soshelp <command>                   Displays help for a command.",
        "loadsymbols <url>                         Loads symbols for all modules.",
        "logclose <path>                           Disables console file logging.",
        "logging <path>                            Enables/disables internal diagnostic logging.",
        "logopen <path>                            Enables console file logging.",
        "modules, lm                               Displays the native modules in the process.",
        "registers, r                              Displays the thread's registers.",
        "runtimes, setruntime <id>                 Lists the runtimes in the target or changes the default runtime.",
        "setclrpath <path>                         Sets the path to load coreclr DAC/DBI files.",
        "setsymbolserver, SetSymbolServer <url>    Enables and sets symbol server support for symbols and module download.",
        "sosflush                                  Resets the internal cached state.",
        "sosstatus                                 Displays internal status.",
        "threads, setthread <thread>               Lists the threads in the target or sets the current thread.",
    ]

    # If a specific command is requested, try to print the most relevant single line
    if arg:
        token = arg.strip().split()[0].lower()
        # Try to find a matching LLDB-style line first
        for ln in LLDB_STATIC_BLOCK:
            head = ln.split()[0].rstrip(',')
            # Also check for alias matches separated by comma in the first token
            aliases = ln.split()[0].split(',') if ',' in ln.split()[0] else [head]
            aliases = [a.strip().lower() for a in aliases]
            if token in aliases:
                gdb.write(ln + "\n")
                return
        # Fall back to our dynamic description
        gdb.write(line_for(token))
        return

    # Print the LLDB-style block first in the exact order
    for ln in LLDB_STATIC_BLOCK:
        gdb.write(ln + "\n")

    # Then print the rest of SOS commands (exclude ones already covered by the block or generic 'help')
    printed = set()
    # Collect aliases we already printed in the LLDB block
    for ln in LLDB_STATIC_BLOCK:
        # extract tokens up to the first double space sequence
        head = ln.split()[0]
        # handle alias heads like 'help,' or 'modules,'
        for alias in [a.strip().lower().rstrip(',') for a in head.split(',')]:
            if alias:
                printed.add(alias)
    printed.update({'help'})

    for cmd in sorted(COMMAND_NAMES):
        if cmd in printed:
            continue
        gdb.write(line_for(cmd))


class SosExecUmbrellaCommand(gdb.Command):
    """sos exec <command> [args] — Fallback dynamic dispatcher for any SOS command."""
    def __init__(self):
        super(SosExecUmbrellaCommand, self).__init__("sos exec", gdb.COMMAND_DATA)
        self.__doc__ = "Dispatch an SOS command dynamically (use if a subcommand isn't registered)."

    def _to_export_candidates(self, cmd: str):
        return _to_export_candidates_common(cmd)

    def invoke(self, arg, from_tty):
        if not SOSCommand.lazy_load_sos():
            return
        parts = arg.strip().split(None, 1) if arg else []
        if not parts:
            gdb.write("Usage: sos exec <command> [args]\n")
            return
        name = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""
        # Clear any prior user-interrupt state at the beginning of an umbrella dispatch
        try:
            if hasattr(SOSCommand, 'gdb_services') and SOSCommand.gdb_services is not None:
                SOSCommand.gdb_services.clear_interrupt()
        except Exception:
            pass
        # If CLR just became available after earlier failures, clear stale error state once
        SOSCommand._maybe_flush_after_runtime_load()

        # LLDB-aligned: deliver bpmd immediately even if CLR not loaded.
        # No pre-CLR queuing or local pending bp planting here; fall through to dispatch.

        
        # For help/soshelp, prefer managed help when CLR is loaded
        if name in ("help", "soshelp"):
            if SOSCommand._is_runtime_loaded() and SOSCommand._try_initialize_hosting_if_needed():
                cmd = b"help"
                args = rest.encode('utf-8')
                try:
                    bridge = getattr(SOSCommand, 'bridge_handle', None)
                    if bridge is not None:
                        dispatch = bridge.DispatchManagedCommand
                        dispatch.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                        dispatch.restype = ctypes.c_int
                        h = dispatch(cmd, args)
                        if h == 0:
                            return
                except Exception:
                    pass
                try:
                    if getattr(SOSCommand, 'sos_dispatch_managed', None):
                        h2 = SOSCommand.sos_dispatch_managed(cmd, args)
                        if h2 == 0:
                            return
                except Exception:
                    pass
            # Fall back to static help if managed isn't available
            _print_sos_help_static(rest)
            return

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

SosPrefixCommand()
SosExecUmbrellaCommand()


class ExtUmbrellaCommand(gdb.Command):
    """ext <command> [args] — Alias for 'sos' umbrella."""
    def __init__(self):
        super(ExtUmbrellaCommand, self).__init__("ext", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        # Delegate to 'sos exec' to allow any SOS command name
        gdb.execute(f"sos exec {arg}")


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

COMMAND_HELP = {
    # A concise, high-level description for each command shown in 'help sos'
    "bpmd": "Break on a managed method (name or token).",
    "clrstack": "Display the managed stack trace for the current thread.",
    "clrthreads": "List managed threads and their states.",
    "dumpheap": "Display GC heap statistics and objects (filterable).",
    "dumpobj": "Dump details about a managed object at an address.",
    "dumpmt": "Display method table details for a type.",
    "dumpclass": "Dump details about a managed EEClass/TypeDesc.",
    "dumpmodule": "Show module information and contained types.",
    "dumpassembly": "Show information about a managed assembly.",
    "dumpalc": "List AssemblyLoadContext instances.",
    "gcroot": "Find object roots that reference the target object.",
    "gcwhere": "Show where an object is located in the GC heap.",
    "threadpool": "Display ThreadPool statistics and queues.",
    "eeheap": "Display segments from the GC and loader heaps.",
    "syncblk": "Display SyncBlock (lock) statistics and owners.",
    "soshelp": "List SOS commands and usage (managed when available).",
    "help": "List SOS commands and usage (same as soshelp).",
    "ip2md": "Map an instruction pointer to its MethodDesc.",
    "name2ee": "Resolve a type/method name to MethodDesc or EEClass.",
    "printexception": "Display the last managed exception (or at address).",
    "pe": "Alias for printexception.",
    "runtimes": "List .NET runtimes loaded in the target.",
    "sosstatus": "Display SOS internal status information.",
    "sosflush": "Flush SOS caches and state (advanced).",
    "loadsymbols": "Configure or trigger symbol loading.",
    "setsymbolserver": "Configure symbol server settings.",
    "logging": "Enable/disable SOS internal logging (managed).",
    "dumpstack": "Show mixed (managed/native) stack trace (best-effort).",
    "dumpstackobjects": "List managed objects on the current stack.",
    "dso": "Alias for dumpstackobjects.",
    "clrmodules": "List managed modules/assemblies in the process.",
    "assemblies": "List assemblies and load contexts.",
    "threadstate": "Display detailed thread state for a managed thread.",
    "gcinfo": "Dump GC info for a JITted method.",
    "dumparray": "Display elements of a managed array.",
    "dumpdelegate": "Dump target and fields of a delegate.",
    "dumpgcdata": "Dump GC internal data structures (advanced).",
    "dumpil": "Display IL for a method.",
    "dumplog": "Dump internal runtime or SOS log (if enabled).",
    "dumpmd": "Display MethodDesc and flags for a method.",
    "dumpsig": "Decode and display a signature blob.",
    "dumpsigelem": "Display a single signature element.",
    "dumpvc": "Display a value class (struct) instance.",
    "eestack": "Display only the managed portion of the stack.",
    "eeversion": "Display CLR version information.",
    "ehinfo": "Display exception handling (EH) clauses for a method.",
    "findappdomain": "Find the app domain for an object/module.",
    "findroots": "Find object roots with filters.",
    "gchandles": "Enumerate GC handles.",
    "histclear": "Clear allocation/stack history information.",
    "histinit": "Initialize allocation/stack history collection.",
    "histobj": "Display allocation history for an object.",
    "histobjfind": "Find objects by allocation history.",
    "histroot": "Display roots recorded in history.",
    "histstats": "Display allocation/stack history statistics.",
    "listnearobj": "List objects near the specified address.",
    "objsize": "Display the size of a managed object graph.",
    "pathto": "Find a path between two objects.",
    "setclrpath": "Set path to CLR binaries (legacy).",
    "stoponcatch": "Enable/disable stop on managed exception catch.",
    "token2ee": "Map metadata token to EE structures.",
}


def _register_default_commands():
    # Full set of commonly used commands (native exports and managed)
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
        "help", "analyzeoom", "assemblies", "clrmodules", "crashinfo", "dumpasync", "dumpheap", "dumphttp",
        "dumpruntimetypes", "dumprequests", "dumpstackobjects", "dso", "eeheap", "gcroot",
        "gcwhere", "listnearobj", "loadsymbols", "logging", "objsize", "pathto", "setsymbolserver",
        "threadpool", "verifyheap", "verifyobj", "traverseheap", "gcheapstat", "finalizequeue",
    ]

    def _mk_cls_for(name: str, helptext: str):
        # Create a dynamic subclass so the class-level __doc__ is unique per command for GDB help
        clsname = "SOSCmd_" + re.sub(r"[^0-9A-Za-z_]", "_", name)
        attrs = {"__doc__": helptext}
        return type(clsname, (SOSCommand,), attrs)

    # 1) Register 'sos <name>' subcommands (prefix-based) with per-command help
    for n in names:
        try:
            helptext = COMMAND_HELP.get(n, f"Run SOS command '{n}'.")
            Cmd = _mk_cls_for(f"sos {n}", helptext)
            Cmd(f"sos {n}")
        except Exception:
            pass

    # 2) Optional top-level aliases (to avoid clutter set SOS_GDB_TOPLEVEL_ALIASES=0)
    if os.environ.get('SOS_GDB_TOPLEVEL_ALIASES', '1').lower() not in ('0', 'false', 'no'):
        for n in names:
            if n == 'help':
                continue  # don't shadow GDB's built-in 'help'
            try:
                helptext = COMMAND_HELP.get(n, f"Run SOS command '{n}'.")
                Cmd = _mk_cls_for(n, helptext)
                Cmd(n)
            except Exception:
                pass


_register_default_commands()

# Register stubs for WinDbg/cdb-only commands so direct invocation prints a clear message.
class UnsupportedSosCommand(gdb.Command):
    def __init__(self, name: str):
        super(UnsupportedSosCommand, self).__init__(name, gdb.COMMAND_SUPPORT)
        self._name = name
        self.__doc__ = "This command is only supported under windbg/cdb currently."

    def invoke(self, arg, from_tty):
        gdb.write("This command is only supported under windbg/cdb currently\n")


for _n in sorted(_UNSUPPORTED_WINDBG_ONLY):
    try:
        UnsupportedSosCommand(_n)
    except Exception:
        pass

# Also register 'sos <name>' stubs for unsupported commands so they appear under 'help sos'
for _n in sorted(_UNSUPPORTED_WINDBG_ONLY):
    try:
        # Create as a separate class instance per name
        class _StubCmd(UnsupportedSosCommand):
            def __init__(self, nm):
                super(_StubCmd, self).__init__(nm)
        _StubCmd(f"sos {_n}")
    except Exception:
        pass


# Thin wrapper utilities and aliases (LLDB-style), registered under 'sos' and safe top-level aliases.
def _register_wrapper_commands():
    def _top_level_ok(name: str) -> bool:
        # Honor env gate and avoid clobbering well-known gdb commands (e.g., 'r' and possibly 'd').
        if os.environ.get('SOS_GDB_TOPLEVEL_ALIASES', '1').lower() in ('0', 'false', 'no'):
            return False
        if name in { 'r', 'd' }:
            return False
        return True

    # Memory dump helpers -----------------------------------------------------
    def _mk_mem_cmd(cmd_name: str, fmt: str, default_count: int, doc: str):
        class _MemCmd(gdb.Command):
            __doc__ = doc
            def __init__(self, nm):
                super(_MemCmd, self).__init__(nm, gdb.COMMAND_DATA)
            def invoke(self, arg, from_tty):
                # Parse: <address> [count]
                addr = None
                count = default_count
                if arg:
                    toks = arg.strip().split()
                    if len(toks) >= 2:
                        # Treat last token as count if it parses
                        try:
                            count = int(toks[-1], 0)
                            addr = ' '.join(toks[:-1])
                        except Exception:
                            addr = arg.strip()
                    else:
                        addr = toks[0]
                if not addr:
                    gdb.write(f"Usage: {cmd_name} <address> [count]\n")
                    return
                try:
                    gdb.execute(f"x/{count}{fmt} {addr}")
                except Exception as ex:
                    gdb.write(f"memory dump failed: {ex}\n")

        # Register under 'sos'
        _MemCmd(f"sos {cmd_name}")
        # Optional top-level alias
        if _top_level_ok(cmd_name):
            try:
                _MemCmd(cmd_name)
            except Exception:
                pass

    # 'd'/'readmemory' generic fallback -> bytes
    class _ReadMemory(gdb.Command):
        __doc__ = "Dumps memory contents (defaults to 64 bytes as hex)."
        def __init__(self, nm):
            super(_ReadMemory, self).__init__(nm, gdb.COMMAND_DATA)
        def invoke(self, arg, from_tty):
            addr = None
            count = 64
            if arg:
                toks = arg.strip().split()
                if len(toks) >= 2:
                    try:
                        count = int(toks[-1], 0)
                        addr = ' '.join(toks[:-1])
                    except Exception:
                        addr = arg.strip()
                else:
                    addr = toks[0]
            if not addr:
                gdb.write("Usage: readmemory <address> [count]\n")
                return
            try:
                gdb.execute(f"x/{count}bx {addr}")
            except Exception as ex:
                gdb.write(f"readmemory failed: {ex}\n")

    # Register the generic readmemory
    _ReadMemory("sos readmemory")
    if _top_level_ok("readmemory"):
        try:
            _ReadMemory("readmemory")
        except Exception:
            pass
    # Provide 'sos d' alias only (avoid top-level 'd' that conflicts with gdb shortcuts)
    try:
        class _D(gdb.Command):
            __doc__ = "Alias of 'readmemory'. Dumps memory contents."
            def __init__(self, nm):
                super(_D, self).__init__(nm, gdb.COMMAND_DATA)
            def invoke(self, arg, from_tty):
                gdb.execute(f"sos readmemory {arg}" if arg else "sos readmemory")
        _D("sos d")
    except Exception:
        pass

    # Specific formats
    _mk_mem_cmd("db", "bx", 64, "Dumps memory as bytes (hex). Usage: db <address> [count]")
    _mk_mem_cmd("dd", "wx", 16, "Dumps memory as dwords (uint32). Usage: dd <address> [count]")
    _mk_mem_cmd("dq", "gx", 8,  "Dumps memory as qwords (uint64). Usage: dq <address> [count]")
    _mk_mem_cmd("dw", "hx", 32, "Dumps memory as words (uint16). Usage: dw <address> [count]")
    # chars as printable characters
    _mk_mem_cmd("dc", "c", 64, "Dumps memory as chars. Usage: dc <address> [count]")

    # Zero-terminated strings
    class _StringDump(gdb.Command):
        __doc__ = "Dumps memory as a zero-terminated char string. Usage: du|da <address>"
        def __init__(self, nm):
            super(_StringDump, self).__init__(nm, gdb.COMMAND_DATA)
        def invoke(self, arg, from_tty):
            addr = (arg or "").strip()
            if not addr:
                gdb.write("Usage: du|da <address>\n")
                return
            try:
                gdb.execute(f"x/s {addr}")
            except Exception as ex:
                gdb.write(f"string dump failed: {ex}\n")

    for nm in ("du", "da"):
        try:
            _StringDump(f"sos {nm}")
            if _top_level_ok(nm):
                _StringDump(nm)
        except Exception:
            pass

    # Pointers
    class _PointerDump(gdb.Command):
        __doc__ = "Dumps memory as pointers. Usage: dp <address> [count]"
        def __init__(self, nm):
            super(_PointerDump, self).__init__(nm, gdb.COMMAND_DATA)
        def invoke(self, arg, from_tty):
            addr = None
            count = 8
            if arg:
                toks = arg.strip().split()
                if len(toks) >= 2:
                    try:
                        count = int(toks[-1], 0)
                        addr = ' '.join(toks[:-1])
                    except Exception:
                        addr = arg.strip()
                else:
                    addr = toks[0]
            if not addr:
                gdb.write("Usage: dp <address> [count]\n")
                return
            try:
                # 'a' prints addresses/symbols; better than raw hex for pointers
                gdb.execute(f"x/{count}a {addr}")
            except Exception as ex:
                gdb.write(f"pointer dump failed: {ex}\n")
    try:
        _PointerDump("sos dp")
        if _top_level_ok("dp"):
            _PointerDump("dp")
    except Exception:
        pass

    # Modules (native) --------------------------------------------------------
    class _Modules(gdb.Command):
        __doc__ = "Displays the native modules in the process."
        def __init__(self, nm):
            super(_Modules, self).__init__(nm, gdb.COMMAND_SUPPORT)
        def invoke(self, arg, from_tty):
            try:
                gdb.write("Native modules (shared libraries):\n")
                out = gdb.execute("info sharedlibrary", to_string=True)
                gdb.write(out)
            except Exception:
                pass
            try:
                gdb.write("\nExecutable and object files:\n")
                out2 = gdb.execute("info files", to_string=True)
                gdb.write(out2)
            except Exception as ex:
                gdb.write(f"modules info note: {ex}\n")
    try:
        _Modules("sos modules")
        _Modules("sos lm")
        if _top_level_ok("modules"):
            _Modules("modules")
        if _top_level_ok("lm"):
            _Modules("lm")
    except Exception:
        pass

    # Registers ---------------------------------------------------------------
    class _Registers(gdb.Command):
        __doc__ = "Displays the thread's registers."
        def __init__(self, nm):
            super(_Registers, self).__init__(nm, gdb.COMMAND_SUPPORT)
        def invoke(self, arg, from_tty):
            try:
                gdb.execute("info registers")
            except Exception as ex:
                gdb.write(f"registers failed: {ex}\n")
    try:
        _Registers("sos registers")
        if _top_level_ok("registers"):
            _Registers("registers")
    except Exception:
        pass

    # Threads / setthread -----------------------------------------------------
    class _Threads(gdb.Command):
        __doc__ = "Lists the threads in the target."
        def __init__(self, nm):
            super(_Threads, self).__init__(nm, gdb.COMMAND_SUPPORT)
        def invoke(self, arg, from_tty):
            try:
                gdb.execute("info threads")
            except Exception as ex:
                gdb.write(f"threads failed: {ex}\n")
    try:
        _Threads("sos threads")
        if _top_level_ok("threads"):
            _Threads("threads")
    except Exception:
        pass

    class _SetThread(gdb.Command):
        __doc__ = "Sets the current thread. Usage: setthread <gdb-thread-id>"
        def __init__(self, nm):
            super(_SetThread, self).__init__(nm, gdb.COMMAND_SUPPORT)
        def invoke(self, arg, from_tty):
            tid = (arg or "").strip()
            if not tid:
                gdb.write("Usage: setthread <gdb-thread-id>\n")
                return
            try:
                gdb.execute(f"thread {tid}")
            except Exception as ex:
                gdb.write(f"setthread failed: {ex}\n")
    try:
        _SetThread("sos setthread")
        if _top_level_ok("setthread"):
            _SetThread("setthread")
    except Exception:
        pass

    # runtimes / setruntime ---------------------------------------------------
    class _SetRuntime(gdb.Command):
        __doc__ = "Changes the default runtime. Usage: setruntime <id> (see 'sos runtimes')"
        def __init__(self, nm):
            super(_SetRuntime, self).__init__(nm, gdb.COMMAND_SUPPORT)
        def invoke(self, arg, from_tty):
            rid = (arg or "").strip()
            if not rid:
                gdb.write("Usage: setruntime <id>\n")
                return
            # Try managed dispatcher: 'runtimes -set <id>' if supported
            try:
                gdb.execute(f"sos exec runtimes -set {rid}")
                return
            except Exception:
                pass
            # Fallback: call directly if export exists or just show runtimes
            try:
                gdb.execute("sos runtimes")
            except Exception as ex:
                gdb.write(f"setruntime fallback failed: {ex}\n")
    try:
        _SetRuntime("sos setruntime")
        if _top_level_ok("setruntime"):
            _SetRuntime("setruntime")
    except Exception:
        pass

    # Logging (console file) --------------------------------------------------
    class _LogOpen(gdb.Command):
        __doc__ = "Enables console file logging. Usage: logopen <path>"
        def __init__(self, nm):
            super(_LogOpen, self).__init__(nm, gdb.COMMAND_SUPPORT)
        def invoke(self, arg, from_tty):
            path = (arg or "").strip()
            if not path:
                gdb.write("Usage: logopen <path>\n")
                return
            try:
                gdb.execute(f"set logging file {path}")
                gdb.execute("set logging overwrite on")
                gdb.execute("set logging on")
                gdb.write(f"Console logging enabled to '{path}'.\n")
            except Exception as ex:
                gdb.write(f"logopen failed: {ex}\n")
    try:
        _LogOpen("sos logopen")
        if _top_level_ok("logopen"):
            _LogOpen("logopen")
    except Exception:
        pass

    class _LogClose(gdb.Command):
        __doc__ = "Disables console file logging. Usage: logclose"
        def __init__(self, nm):
            super(_LogClose, self).__init__(nm, gdb.COMMAND_SUPPORT)
        def invoke(self, arg, from_tty):
            try:
                gdb.execute("set logging off")
                gdb.write("Console logging disabled.\n")
            except Exception as ex:
                gdb.write(f"logclose failed: {ex}\n")
    try:
        _LogClose("sos logclose")
        if _top_level_ok("logclose"):
            _LogClose("logclose")
    except Exception:
        pass

    # SetSymbolServer (capitalized alias) ------------------------------------
    class _SetSymbolServerAlias(gdb.Command):
        __doc__ = "Alias to setsymbolserver. Usage: SetSymbolServer <url>"
        def __init__(self, nm):
            super(_SetSymbolServerAlias, self).__init__(nm, gdb.COMMAND_SUPPORT)
        def invoke(self, arg, from_tty):
            try:
                gdb.execute(f"sos setsymbolserver {arg}" if arg else "sos setsymbolserver")
            except Exception as ex:
                gdb.write(f"SetSymbolServer failed: {ex}\n")
    try:
        _SetSymbolServerAlias("sos SetSymbolServer")
        if _top_level_ok("SetSymbolServer"):
            _SetSymbolServerAlias("SetSymbolServer")
    except Exception:
        pass


_register_wrapper_commands()
