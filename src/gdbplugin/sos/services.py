import os
import sys
import ctypes
import gdb
import re

# Allow importing when sourced directly (sos.py adjusts sys.path similarly)
from abi import *
from tracing import TRACE_ENABLED, trace, trace_cat


class GdbServices:
    """Implements the SOS services interfaces in Python."""
    def __init__(self):
        self._ref = 0
        self._coreclr_base = None
        self._coreclr_path = None
        self._coreclr_dir_buf = None
        self._current_thread_sysid = None  # cached OS thread id (LWP)
        # Cache of last known register context per system thread id to serve
        # offset queries without touching gdb APIs from foreign threads.
        self._context_cache = {}  # sysid -> { 'rip': int, 'rsp': int, 'rbp': int }
        # Track if user interrupted output (e.g., pressed 'q' in pager)
        self._interrupted = False
        # Runtime-loaded callback/corresponding gdb breakpoint
        self._runtime_loaded_cb = None
        self._runtime_loaded_bp = None
        # Exception callback registered by SOS (invoked on CLR notifications)
        self._exception_cb = None
        # Stop-event hook state
        self._stop_hook_registered = False
        self._in_stop = False
        self._stop_handler = self._make_stop_handler()
        # New objfile (shared library) hook to detect libcoreclr load
        self._newobj_hook_registered = False
        self._newobj_handler = self._make_newobj_handler()
        # Track whether runtime-loaded callback has fired to avoid duplicates
        self._runtime_loaded_fired = False
        # Consider the runtime ready only after the entry breakpoint fires
        self._runtime_initialized = False
        # Optional hook provided by sos.py to update the managed host target PID via bridge
        # Set to a callable(pid:int)->HRESULT when the bridge is available; else None
        self._bridge_update_fn = None
        # Track if a continue() has been scheduled to avoid duplicate requests
        self._continue_pending = False

        iunknown_vtbl = IUnknownVtbl(QI_FUNC_TYPE(self.query_interface), ADDREF_FUNC_TYPE(self.add_ref), RELEASE_FUNC_TYPE(self.release))

        self._imemory_vtbl = IMemoryServiceVtbl(iunknown_vtbl, READ_VIRTUAL_FUNC_TYPE(self.read_virtual))
        self._idebugger_vtbl = IDebuggerServicesVtbl(
            iunknown_vtbl,
            GET_OPERATING_SYSTEM_FUNC_TYPE(self.dbg_get_operating_system),
            DBG_GET_DEBUGGEE_TYPE_FUNC_TYPE(self.lldb_get_debuggee_type),
            DBG_GET_PROCESSOR_TYPE_FUNC_TYPE(self.lldb_get_processor_type),
            DBG_ADD_COMMAND_FUNC_TYPE(self.dbg_add_command),
            DBG_OUTPUT_STRING_FUNC_TYPE(self.dbg_output_string),
            DBG_READ_VIRTUAL_FUNC_TYPE(self.lldb_read_virtual),
            DBG_WRITE_VIRTUAL_FUNC_TYPE(self.lldb_write_virtual),
            DBG_GET_NUMBER_MODULES_FUNC_TYPE(self.lldb_get_number_modules),
            DBG_GET_MODULE_BY_INDEX_FUNC_TYPE(self.lldb_get_module_by_index),
            DBG_GET_MODULE_NAMES_FUNC_TYPE(self.dbg_get_module_names),
            DBG_GET_MODULE_INFO_FUNC_TYPE(self.dbg_get_module_info),
            DBG_GET_MODULE_VERSION_INFO_FUNC_TYPE(self.lldb2_get_module_version_information),
            DBG_GET_MODULE_BY_MODNAME_FUNC_TYPE(self.lldb_get_module_by_module_name),
            DBG_GET_NUMBER_THREADS_FUNC_TYPE(self.dbg_get_number_threads),
            DBG_GET_THREAD_IDS_BY_INDEX_FUNC_TYPE(self.dbg_get_thread_ids_by_index),
            DBG_GET_THREAD_CONTEXT_BY_SYSID_FUNC_TYPE(self.lldb_get_thread_context_by_system_id),
            DBG_GET_CURRENT_PROCESS_SYSID_FUNC_TYPE(self.lldb_get_current_process_system_id),
            DBG_GET_CURRENT_THREAD_SYSID_FUNC_TYPE(self.lldb_get_current_thread_system_id),
            DBG_SET_CURRENT_THREAD_SYSID_FUNC_TYPE(self.dbg_set_current_thread_system_id),
            DBG_GET_THREAD_TEB_FUNC_TYPE(self.dbg_get_thread_teb),
            DBG_VIRTUAL_UNWIND_FUNC_TYPE(self.lldb_virtual_unwind),
            DBG_GET_SYMBOL_PATH_FUNC_TYPE(self.dbg_get_symbol_path),
            DBG_GET_SYMBOL_BY_OFFSET_FUNC_TYPE(self.dbg_get_symbol_by_offset),
            DBG_GET_OFFSET_BY_SYMBOL_FUNC_TYPE(self.dbg_get_offset_by_symbol),
            DBG_GET_TYPE_ID_FUNC_TYPE(self.dbg_get_type_id),
            DBG_GET_FIELD_OFFSET_FUNC_TYPE(self.dbg_get_field_offset),
            DBG_GET_OUTPUT_WIDTH_FUNC_TYPE(self.dbg_get_output_width),
            DBG_SUPPORTS_DML_FUNC_TYPE(self.dbg_supports_dml),
            DBG_OUTPUT_DML_STRING_FUNC_TYPE(self.dbg_output_dml_string),
            DBG_ADD_MODULE_SYMBOL_FUNC_TYPE(self.lldb2_add_module_symbol),
            DBG_GET_LAST_EVENT_INFO_FUNC_TYPE(self.lldb_get_last_event_information),
            DBG_FLUSH_CHECK_FUNC_TYPE(self.dbg_flush_check),
            DBG_EXECUTE_HOST_COMMAND_FUNC_TYPE(self.dbg_execute_host_command),
            DBG_GET_DAC_SIG_VER_SETTINGS_FUNC_TYPE(self.dbg_get_dac_signature_ver_settings),
        )
        self._ihost_vtbl = IHostVtbl(iunknown_vtbl, GET_HOST_TYPE_FUNC_TYPE(self.host_get_host_type), GET_SERVICE_FUNC_TYPE(self.host_get_service), GET_CURRENT_TARGET_FUNC_TYPE(self.host_get_current_target))
        self._ihostservices_vtbl = IHostServicesVtbl(
            iunknown_vtbl,
            HOSTSERVICES_GETHOST(self.hostservices_get_host),
            HOSTSERVICES_REGISTERDEBUGGER(self.hostservices_register_debugger_services),
            HOSTSERVICES_CREATETARGET(self.hostservices_create_target),
            HOSTSERVICES_UPDATETARGET(self.hostservices_update_target),
            HOSTSERVICES_FLUSHTARGET(self.hostservices_flush_target),
            HOSTSERVICES_DESTROYTARGET(self.hostservices_destroy_target),
            HOSTSERVICES_DISPATCHCOMMAND(self.hostservices_dispatch_command),
            HOSTSERVICES_UNINITIALIZE(self.hostservices_uninitialize),
        )
        self._illldb_vtbl = ILLDBServicesVtbl(
            iunknown_vtbl,
            ctypes.CFUNCTYPE(PCSTR, PVOID)(self.lldb_get_coreclr_directory),
            ctypes.CFUNCTYPE(ULONG64, PVOID, PCSTR)(self.lldb_get_expression),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG, PVOID)(self.lldb_virtual_unwind),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID)(self.lldb_set_exception_callback),
            ctypes.CFUNCTYPE(HRESULT, PVOID)(self.lldb_clear_exception_callback),
            ctypes.CFUNCTYPE(HRESULT, PVOID)(self.lldb_get_interrupt),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, PVOID)(self.lldb_output_va_list),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))(self.lldb_get_debuggee_type),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))(self.lldb_get_page_size),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))(self.lldb_get_processor_type),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ULONG)(self.lldb_execute),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG), ctypes.POINTER(ULONG), PVOID, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG))(self.lldb_get_last_event_information),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ULONG, ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))(self.lldb_disassemble),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID, ULONG, PVOID, ULONG, PVOID, ULONG, ULONG, ctypes.POINTER(ULONG))(self.lldb_get_context_stack_trace),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))(self.lldb_read_virtual),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))(self.lldb_write_virtual),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))(self.lldb_get_symbol_options),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))(self.lldb_get_name_by_offset),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))(self.lldb_get_number_modules),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64))(self.lldb_get_module_by_index),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))(self.lldb_get_module_by_module_name),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))(self.lldb_get_module_by_offset),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG))(self.lldb_get_module_names),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))(self.lldb_get_line_by_offset),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ctypes.POINTER(ULONG64), ULONG, ctypes.POINTER(ULONG))(self.lldb_get_source_file_line_offsets),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG))(self.lldb_find_source_file),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))(self.lldb_get_current_process_system_id),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))(self.lldb_get_current_thread_id),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG)(self.lldb_set_current_thread_id),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))(self.lldb_get_current_thread_system_id),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG))(self.lldb_get_thread_id_by_system_id),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG, ULONG, PVOID)(self.lldb_get_thread_context_by_system_id),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ctypes.POINTER(ctypes.c_size_t))(self.lldb_get_value_by_name),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG64))(self.lldb_get_instruction_offset),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG64))(self.lldb_get_stack_offset),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG64))(self.lldb_get_frame_offset),
        )
        self._illldb2_vtbl = ILLDBServices2Vtbl(
            iunknown_vtbl,
            ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.c_bool, PVOID)(self.lldb2_load_native_symbols),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID, PCSTR)(self.lldb2_add_module_symbol),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64), ctypes.POINTER(ULONG64), ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))(self.lldb2_get_module_info),
            ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, PCSTR, PVOID, ULONG, ctypes.POINTER(ULONG))(self.lldb2_get_module_version_information),
            ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID)(self.lldb2_set_runtime_loaded_callback),
        )
        self.imemory_ptr = IMemoryService(ctypes.pointer(self._imemory_vtbl))
        self.idebugger_ptr = IDebuggerServices(ctypes.pointer(self._idebugger_vtbl))
        self.ihost_ptr = IHost(ctypes.pointer(self._ihost_vtbl))
        self.ihostservices_ptr = IHostServices(ctypes.pointer(self._ihostservices_vtbl))
        self.illldb_ptr = ILLDBServices(ctypes.pointer(self._illldb_vtbl))
        self.illldb2_ptr = ILLDBServices2(ctypes.pointer(self._illldb2_vtbl))
        # Minimal native ITarget implementation (COM-like) exposed to SOS when host path is active
        self._itarget_vtbl = ITargetVtbl(
            iunknown_vtbl,
            TARGET_GET_OS_FUNC_TYPE(self.target_get_operating_system),
            TARGET_GET_SERVICE_FUNC_TYPE(self.target_get_service),
            TARGET_GET_RUNTIME_FUNC_TYPE(self.target_get_runtime),
            TARGET_FLUSH_FUNC_TYPE(self.target_flush),
        )
        self.itarget_ptr = ITarget(ctypes.pointer(self._itarget_vtbl))
        # Minimal native IRuntime implementation
        self._iruntime_vtbl = IRuntimeVtbl(
            iunknown_vtbl,
            RUNTIME_GET_CONFIG_FUNC_TYPE(self.runtime_get_config),
            RUNTIME_GET_MODULE_ADDR_FUNC_TYPE(self.runtime_get_module_address),
            RUNTIME_GET_MODULE_SIZE_FUNC_TYPE(self.runtime_get_module_size),
            RUNTIME_SET_DIR_FUNC_TYPE(self.runtime_set_runtime_directory),
            RUNTIME_GET_DIR_FUNC_TYPE(self.runtime_get_runtime_directory),
            RUNTIME_GET_CLRDATA_PROC_FUNC_TYPE(self.runtime_get_clr_data_process),
            RUNTIME_GET_CORDEBUG_FUNC_TYPE(self.runtime_get_cordebug_interface),
            RUNTIME_GET_EEVERSION_FUNC_TYPE(self.runtime_get_ee_version),
        )
        self.iruntime_ptr = IRuntime(ctypes.pointer(self._iruntime_vtbl))
        # Cache runtime config and size
        self._runtime_config = 2  # IRuntime::UnixCore (same as Core on FEATURE_PAL Linux)
        self._runtime_dir_override = None
        self._coreclr_size = 0
        self._registered_debugger = None
        # DAC state
        self._dac_handle = None
        self._clrdata_process = None  # Cached IXCLRDataProcess*
        # Build ICLRDataTarget2 implementation vtable
        self._dt_iunknown_vtbl = IUnknownVtbl(QI_FUNC_TYPE(self._dt_query_interface), ADDREF_FUNC_TYPE(self._dt_add_ref), RELEASE_FUNC_TYPE(self._dt_release))
        self._dt_vtbl = ICLRDataTarget2Vtbl(
            self._dt_iunknown_vtbl,
            DT_GET_MACHINE_TYPE(self._dt_get_machine_type),
            DT_GET_POINTER_SIZE(self._dt_get_pointer_size),
            DT_GET_IMAGE_BASE(self._dt_get_image_base),
            DT_READ_VIRTUAL(self._dt_read_virtual),
            DT_WRITE_VIRTUAL(self._dt_write_virtual),
            DT_GET_TLS_VALUE(self._dt_get_tls_value),
            DT_SET_TLS_VALUE(self._dt_set_tls_value),
            DT_GET_CUR_THREAD_ID(self._dt_get_current_thread_id),
            DT_GET_THREAD_CONTEXT(self._dt_get_thread_context),
            DT_SET_THREAD_CONTEXT(self._dt_set_thread_context),
            DT_REQUEST(self._dt_request),
            DT_ALLOC_VIRTUAL(self._dt_alloc_virtual),
            DT_FREE_VIRTUAL(self._dt_free_virtual),
        )
        self._dt_ptr = ICLRDataTarget2(ctypes.pointer(self._dt_vtbl))
        self._dt_ref = 0
    # (Removed) Python-layer auto-continue guard; GDB flow now mirrors LLDB: native runtime-loaded callback is responsible for a single continue.

        # Proactively connect new-objfile hook so we never miss libcoreclr.so load
        # even if SOS registers callbacks later. This handler is one-shot and
        # will disconnect itself after firing.
        try:
            if not self._newobj_hook_registered:
                gdb.events.new_objfile.connect(self._newobj_handler)
                self._newobj_hook_registered = True
                trace_cat('bpmd', '[new-objfile] connected (early)')
        except Exception:
            pass

        # Disable pagination to avoid interactive prompts that block auto-continue
        try:
            gdb.execute('set pagination off', to_string=True)
        except Exception:
            pass

    def _schedule_safe_continue(self):
        """Schedule a safe asynchronous 'continue' to avoid reentrancy during callbacks."""
        try:
            if getattr(self, '_continue_pending', False):
                return
            self._continue_pending = True

            def _do_continue():
                try:
                    try:
                        trace_cat('bpmd', "[continue] _schedule_safe_continue: invoking 'continue' (async posted)")
                    except Exception:
                        pass
                    gdb.execute('continue', to_string=True)
                except Exception:
                    pass
                finally:
                    try:
                        self._continue_pending = False
                    except Exception:
                        pass
            # Post the continue to GDB's event loop to avoid reentrancy
            try:
                gdb.post_event(_do_continue)
            except Exception:
                # Fallback: call directly if posting fails
                _do_continue()
        except Exception:
            # As a last resort, try to continue synchronously (may be ignored by GDB)
            try:
                gdb.execute('continue', to_string=True)
            except Exception:
                pass

    def _is_core_dump_session(self) -> bool:
        """Detect if the current GDB session is a real core dump debugging session.
        We can't rely on PID before 'run' (it may be None), and SOS may cache IsDumpFile early.
        Parse 'info files' for core dump indicators to distinguish real dumps from live.
        """
        # Optional caching to avoid repeated 'info files' during scenarios
        try:
            no_cache = os.environ.get('SOS_COREDUMP_DETECT_NO_CACHE') in ('1','true','True')
        except Exception:
            no_cache = False
        if not no_cache:
            try:
                if hasattr(self, '_cached_is_core_dump'):
                    if TRACE_ENABLED:
                        try:
                            gdb.write(f"[sos] core-dump detection: {'core' if self._cached_is_core_dump else 'live'} (cached=True)\n")
                        except Exception:
                            pass
                    return bool(self._cached_is_core_dump)
            except Exception:
                pass
        try:
            out = gdb.execute('info files', to_string=True)
        except Exception:
            if TRACE_ENABLED:
                try:
                    gdb.write("[sos] core-dump detection: live (cached=False)\n")
                except Exception:
                    pass
            if not no_cache:
                try:
                    self._cached_is_core_dump = False
                except Exception:
                    pass
            return False
        if not out:
            if TRACE_ENABLED:
                try:
                    gdb.write("[sos] core-dump detection: live (cached=False)\n")
                except Exception:
                    pass
            if not no_cache:
                try:
                    self._cached_is_core_dump = False
                except Exception:
                    pass
            return False
        text = out.lower()
        patterns = (
            'core file',
            'local core dump file',
            'core was generated by',
            'core from',
        )
        result = any(p in text for p in patterns)
        if TRACE_ENABLED:
            try:
                gdb.write(f"[sos] core-dump detection: {'core' if result else 'live'} (cached=False)\n")
            except Exception:
                pass
        if not no_cache:
            try:
                self._cached_is_core_dump = bool(result)
            except Exception:
                pass
        return result

    # --- IUnknown ---
    def _guid_bytes_le(self, g: GUID) -> bytes:
        return ctypes.string_at(ctypes.byref(g), ctypes.sizeof(GUID))

    def _guid_equal(self, a: GUID, b: GUID) -> bool:
        return self._guid_bytes_le(a) == self._guid_bytes_le(b)

    def query_interface(self, this_ptr, iid_ptr, obj_ptr):
        iid = iid_ptr.contents
        if TRACE_ENABLED:
            try:
                import uuid
                guid_str = str(uuid.UUID(bytes_le=self._guid_bytes_le(iid))).upper()
                gdb.write(f"QueryInterface called for IID {guid_str}\n")
            except Exception:
                pass

        if self._guid_equal(iid, IID_IUnknown) or self._guid_equal(iid, IID_IDebuggerServices):
            obj_ptr.contents.value = ctypes.addressof(self.idebugger_ptr)
            if TRACE_ENABLED:
                gdb.write("QI -> IDebuggerServices\n")
            self.add_ref(this_ptr)
            return 0
        if self._guid_equal(iid, IID_IMemoryService):
            obj_ptr.contents.value = ctypes.addressof(self.imemory_ptr)
            if TRACE_ENABLED:
                gdb.write("QI -> IMemoryService\n")
            self.add_ref(this_ptr)
            return 0
        if self._guid_equal(iid, IID_IHost):
            obj_ptr.contents.value = ctypes.addressof(self.ihost_ptr)
            if TRACE_ENABLED:
                gdb.write("QI -> IHost\n")
            self.add_ref(this_ptr)
            return 0
        if self._guid_equal(iid, IID_ILLDBServices):
            obj_ptr.contents.value = ctypes.addressof(self.illldb_ptr)
            if TRACE_ENABLED:
                gdb.write("QI -> ILLDBServices (stub)\n")
            self.add_ref(this_ptr)
            return 0
        if self._guid_equal(iid, IID_ILLDBServices2):
            obj_ptr.contents.value = ctypes.addressof(self.illldb2_ptr)
            if TRACE_ENABLED:
                gdb.write("QI -> ILLDBServices2 (stub)\n")
            self.add_ref(this_ptr)
            return 0
        obj_ptr.contents.value = 0
        if TRACE_ENABLED:
            gdb.write("QI -> E_NOINTERFACE\n")
        return 0x80004002

    def add_ref(self, this_ptr):
        self._ref += 1
        return self._ref

    def release(self, this_ptr):
        self._ref -= 1
        return self._ref

    # --- Helpers ---
    def _detect_arch_name(self) -> str:
        """Best-effort architecture name from GDB or OS. Examples: 'i386:x86-64', 'aarch64'."""
        # 1) GDB current frame architecture
        try:
            fr = gdb.newest_frame()
            if fr is not None:
                arch = fr.architecture()
                name = getattr(arch, 'name', None)
                if name:
                    return str(name).lower()
        except Exception:
            pass
        # 2) 'show architecture' output
        try:
            out = gdb.execute('show architecture', to_string=True) or ''
            low = out.lower()
            # try to extract the current arch in parens
            # e.g. "The target architecture is set automatically (currently aarch64)"
            m = re.search(r"currently\s+([^\)\n]+)\)", low)
            if m:
                return m.group(1).strip()
        except Exception:
            pass
        # 3) OS uname
        try:
            return (os.uname().machine or '').lower()
        except Exception:
            return ''

    def _detect_machine_type(self) -> int:
        """Return IMAGE_FILE_MACHINE_* constant based on arch; support x64 and arm64."""
        name = self._detect_arch_name()
        if 'aarch64' in name or 'arm64' in name:
            return IMAGE_FILE_MACHINE_ARM64
        # common x64 names
        if 'x86-64' in name or 'x86_64' in name or 'amd64' in name or 'i386:x86-64' in name:
            return IMAGE_FILE_MACHINE_AMD64
        # Fallback: infer from pointer size
        try:
            if ctypes.sizeof(ctypes.c_void_p) == 8:
                return IMAGE_FILE_MACHINE_AMD64
        except Exception:
            pass
        return IMAGE_FILE_MACHINE_AMD64

    def _detect_pointer_size(self) -> int:
        try:
            # Prefer GDB type system if available
            t = gdb.lookup_type('void').pointer()
            sz = int(getattr(t, 'sizeof', 0) or 0)
            if sz:
                return sz
        except Exception:
            pass
        try:
            return ctypes.sizeof(ctypes.c_void_p)
        except Exception:
            return 8

    def _get_pid(self):
        try:
            inf = gdb.selected_inferior()
            pid = getattr(inf, 'pid', None)
            if pid and pid > 0:
                return pid
        except Exception:
            pass
        return None

    def _scan_coreclr(self):
        pid = self._get_pid()
        if not pid:
            return None, None
        maps_path = f"/proc/{pid}/maps"
        found_path = None
        base = None
        try:
            with open(maps_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if 'libcoreclr.so' not in line:
                        continue
                    parts = line.rstrip('\n').split()
                    if len(parts) < 6:
                        continue
                    addr_range = parts[0]
                    path_field = ' '.join(parts[5:])
                    if path_field.endswith(' (deleted)'):
                        path_field = path_field[:-10]
                    path = path_field if path_field.startswith('/') else None
                    if not path:
                        continue
                    try:
                        start_str = addr_range.split('-')[0]
                        start = int(start_str, 16)
                    except Exception:
                        continue
                    if found_path is None:
                        found_path = path
                        base = start
                    else:
                        if start < base:
                            base = start
            if found_path:
                self._coreclr_path = found_path
                self._coreclr_base = base
                directory = os.path.dirname(found_path)
                if directory:
                    path_bytes = directory.encode('utf-8')
                    self._coreclr_dir_buf = ctypes.create_string_buffer(path_bytes + b"\x00")
                trace(f"_scan_coreclr found path={self._coreclr_path} base=0x{self._coreclr_base:x}")
                return self._coreclr_path, self._coreclr_base
        except Exception as ex:
            trace(f"_scan_coreclr error: {ex}")
        self._coreclr_path = None
        self._coreclr_base = None
        self._coreclr_dir_buf = None
        return None, None

    def _get_threads(self):
        try:
            inf = gdb.selected_inferior()
            return list(inf.threads()) if inf else []
        except Exception:
            return []

    def _canon_modname(self, name: str) -> str:
        """Return a canonical module name without platform-specific prefix/suffix.
        Examples:
          'libcoreclr.so' -> 'coreclr'
          'coreclr.dll'   -> 'coreclr'
          'libmscordaccore.so' -> 'mscordaccore'
        """
        try:
            n = (name or '').lower()
            n = os.path.basename(n)
            if n.startswith('lib'):
                n = n[3:]
            if n.endswith('.so'):
                n = n[:-3]
            if n.endswith('.dll'):
                n = n[:-4]
            return n
        except Exception:
            return (name or '').lower()

    def _thread_sysid(self, thread: gdb.InferiorThread):
        try:
            ptid = thread.ptid  # (pid, lwpid, tid?)
            if isinstance(ptid, tuple) and len(ptid) >= 2:
                return int(ptid[1])
            if isinstance(ptid, tuple) and len(ptid) >= 3 and ptid[2]:
                return int(ptid[2])
        except Exception:
            pass
        try:
            return int(thread.ptid[0])
        except Exception:
            return 0

    def _find_thread_by_sysid(self, sysid: int):
        for t in self._get_threads():
            try:
                if self._thread_sysid(t) == sysid:
                    return t
            except Exception:
                continue
        return None

    def _fill_amd64_dt_context(self, frame, contextFlags, context_ptr):
        try:
            # DT_CONTEXT_AMD64 | CONTROL | INTEGER
            # Map: Rip, Rsp, Rbp and Rax..R15
            regs = {
                'rip': ('Rip',), 'rsp': ('Rsp',), 'rbp': ('Rbp',), 'rax': ('Rax',), 'rbx': ('Rbx',), 'rcx': ('Rcx',),
                'rdx': ('Rdx',), 'rsi': ('RSi','Rsi'), 'rdi': ('RDy','Rdi'), 'r8': ('R8',), 'r9': ('R9',), 'r10': ('R10',),
                'r11': ('R11',), 'r12': ('R12',), 'r13': ('R13',), 'r14': ('R14',), 'r15': ('R15',)
            }
            # Helper to set a 64-bit field in DT_CONTEXT by name
            class DT_AMD64(ctypes.Structure):
                _fields_ = [
                    ("pad1", ctypes.c_byte * 120),  # up to Rax
                    ("Rax", ULONG64), ("Rcx", ULONG64), ("Rdx", ULONG64), ("Rbx", ULONG64),
                    ("Rsp", ULONG64), ("Rbp", ULONG64), ("Rsi", ULONG64), ("Rdi", ULONG64),
                    ("R8", ULONG64), ("R9", ULONG64), ("R10", ULONG64), ("R11", ULONG64),
                    ("R12", ULONG64), ("R13", ULONG64), ("R14", ULONG64), ("R15", ULONG64),
                    ("Rip", ULONG64)
                ]
            # Treat context_ptr as a DT_AMD64*
            dt = ctypes.cast(context_ptr, ctypes.POINTER(DT_AMD64)).contents
            for gdb_name, field_names in regs.items():
                try:
                    val = int(frame.read_register(gdb_name))
                except Exception:
                    continue
                for fname in field_names:
                    if hasattr(dt, fname):
                        setattr(dt, fname, val)
                        break
        except Exception as ex:
            trace(f"_fill_amd64_dt_context error: {ex}")

    # --- GDB stop hook wiring ---
    def _make_stop_handler(self):
        # Create a stable function object for connect/disconnect that calls back into this instance
        def _on_stop(event):
            try:
                if self._in_stop:
                    return
                self._in_stop = True
                # Only notify SOS when it registered a callback and CoreCLR is present
                if not getattr(self, "_exception_cb", None):
                    return
                # Detect if this stop was caused by a C++ throw catchpoint so we can auto-continue in fallback mode only
                is_cpp_throw = False
                try:
                    bps = getattr(event, 'breakpoints', None)
                    if bps:
                        for bp in bps:
                            try:
                                loc = (getattr(bp, 'location', '') or '').lower()
                                # Robust detection without depending on BP_CATCHPOINT constant
                                if ('throw' in loc) or ('__cxa_throw' in loc):
                                    is_cpp_throw = True
                                    break
                            except Exception:
                                pass
                except Exception:
                    pass
                # Fallback: inspect current function/symbol name to detect __cxa_throw
                if not is_cpp_throw:
                    try:
                        fr = gdb.newest_frame()
                        fn = None
                        try:
                            sym = fr.function() if fr else None
                            fn = (getattr(sym, 'print_name', None) or getattr(sym, 'name', None) or '')
                        except Exception:
                            fn = ''
                        if isinstance(fn, str) and '__cxa_throw' in fn:
                            is_cpp_throw = True
                        elif not is_cpp_throw:
                            try:
                                s = gdb.execute('info symbol $pc', to_string=True) or ''
                                if '__cxa_throw' in s:
                                    is_cpp_throw = True
                            except Exception:
                                pass
                    except Exception:
                        pass
                # Defer exception notifications until runtime entry has been reached
                if not getattr(self, "_runtime_initialized", False):
                    # Check if we've stopped at the runtime entry and mark initialized
                    try:
                        at_entry = False
                        # Prefer BreakpointEvent inspection when available (more reliable than symbol lookup)
                        try:
                            bps = getattr(event, 'breakpoints', None)
                            if bps:
                                for bp in bps:
                                    loc = (getattr(bp, 'location', '') or '').lower()
                                    if 'coreclr_execute_assembly' in loc:
                                        at_entry = True
                                        break
                        except Exception:
                            pass
                        try:
                            fr = gdb.newest_frame()
                            fn = None
                            try:
                                sym = fr.function() if fr else None
                                fn = getattr(sym, 'print_name', None) or getattr(sym, 'name', None)
                            except Exception:
                                fn = None
                            if isinstance(fn, str) and 'coreclr_execute_assembly' in fn:
                                at_entry = True
                        except Exception:
                            # Fallback via textual symbol query
                            try:
                                s = gdb.execute('info symbol $pc', to_string=True)
                                at_entry = ('coreclr_execute_assembly' in (s or ''))
                            except Exception:
                                at_entry = False
                        if at_entry:
                            self._runtime_initialized = True
                            # Fire runtime-loaded once here if not already fired
                            try:
                                if getattr(self, "_runtime_loaded_cb", None) and not getattr(self, "_runtime_loaded_fired", False):
                                    CBTYPE = ctypes.CFUNCTYPE(HRESULT, ctypes.c_void_p)
                                    cb = ctypes.cast(self._runtime_loaded_cb, CBTYPE)
                                    hr = cb(ctypes.c_void_p(ctypes.addressof(self.illldb_ptr)))
                                    h = int(hr) & 0xFFFFFFFF
                                    trace_cat('bpmd', f"[stop-hook] runtime-loaded via entry HR=0x{h:08x}")
                                    if h == 0:
                                        self._runtime_loaded_fired = True
                                        # Immediately pump exception notifications once to trigger binding
                                        if getattr(self, "_exception_cb", None):
                                            try:
                                                ETYPE = ctypes.CFUNCTYPE(HRESULT, ctypes.c_void_p)
                                                ecb2 = ctypes.cast(self._exception_cb, ETYPE)
                                                ehr2 = ecb2(ctypes.c_void_p(ctypes.addressof(self.illldb_ptr)))
                                                trace_cat('bpmd', f"[stop-hook] exception after runtime-loaded HR=0x{int(ehr2) & 0xFFFFFFFF:08x}")
                                                # Schedule a safe continue so we don't present a stop here (runtime entry only)
                                                self._schedule_safe_continue()
                                                return
                                            except Exception as ex2:
                                                trace(f"[stop-hook] post-runtime exception invoke error: {ex2}")
                            except Exception as rex:
                                trace(f"[stop-hook] runtime-loaded invoke error: {rex}")
                        else:
                            return
                    except Exception:
                        return
                # After runtime is initialized, only handle C++ throw stops; ignore other stops
                if not is_cpp_throw:
                    return
                path, base = self._scan_coreclr()
                if not path or base is None:
                    return
                ETYPE = ctypes.CFUNCTYPE(HRESULT, ctypes.c_void_p)
                ecb = ctypes.cast(self._exception_cb, ETYPE)
                # Mark that we are in a callback-driven execute phase to let Execute() know
                self._in_exception_callback = True
                try:
                    trace_cat('bpmd', '[stop-hook] handling C++ throw; invoking exception callback')
                except Exception:
                    pass
                hr = ecb(ctypes.c_void_p(ctypes.addressof(self.illldb_ptr)))
                try:
                    trace_cat('bpmd', f"[stop-hook] Exception callback HR=0x{int(hr) & 0xFFFFFFFF:08x}")
                except Exception:
                    pass
                # Auto-continue silently for exception notifications
                self._schedule_safe_continue()
                return
            except Exception as ex:
                trace(f"[stop-hook] error: {ex}")
            finally:
                try:
                    self._in_exception_callback = False
                except Exception:
                    pass
                self._in_stop = False
        return _on_stop

    # --- GDB new objfile hook wiring ---
    def _make_newobj_handler(self):
        def _on_newobj(event):
            try:
                # Try to get the filename from event
                obj = getattr(event, 'new_objfile', None)
                fname = getattr(obj, 'filename', None) if obj is not None else None
                if not fname:
                    return
                if os.path.basename(fname) != 'libcoreclr.so':
                    return
                trace_cat('bpmd', f"[new-objfile] detected {fname}")
                # Proactively update managed target PID so managed host can enumerate runtimes
                try:
                    self._update_host_target_pid_if_possible()
                except Exception as exu:
                    trace(f"[new-objfile] UpdateManagedTarget note: {exu}")
                # Do not invoke callbacks or install throw catchpoints here. We defer to:
                #  - runtime entry breakpoint to invoke RuntimeLoaded
                #  - persistent C++ throw catchpoint installed when SetExceptionCallback is called
                # One-shot: we can disconnect this hook after firing
                try:
                    gdb.events.new_objfile.disconnect(self._newobj_handler)
                    self._newobj_hook_registered = False
                    trace("[new-objfile] disconnected")
                except Exception:
                    pass
            except Exception as ex:
                trace(f"[new-objfile] error: {ex}")
        return _on_newobj

    def _invoke_exception_cb_once(self):
        try:
            if not getattr(self, "_exception_cb", None):
                return
            path, base = self._scan_coreclr()
            if not path or base is None:
                return
            ETYPE = ctypes.CFUNCTYPE(HRESULT, ctypes.c_void_p)
            ecb = ctypes.cast(self._exception_cb, ETYPE)
            hr = ecb(ctypes.c_void_p(ctypes.addressof(self.illldb_ptr)))
            trace_cat('bpmd', f"[invoke] Exception callback HR=0x{int(hr) & 0xFFFFFFFF:08x}")
        except Exception as ex:
            trace(f"[invoke] exception-cb error: {ex}")

    def _invoke_runtime_loaded_cb_once(self):
        try:
            if self._runtime_loaded_fired:
                return
            if not getattr(self, "_runtime_loaded_cb", None):
                return
            path, base = self._scan_coreclr()
            if not path or base is None:
                return
            # Ensure managed host target knows the PID before firing callback
            try:
                self._update_host_target_pid_if_possible()
            except Exception as exu:
                trace(f"[invoke] UpdateManagedTarget note: {exu}")
            CBTYPE = ctypes.CFUNCTYPE(HRESULT, ctypes.c_void_p)
            cb = ctypes.cast(self._runtime_loaded_cb, CBTYPE)
            hr = cb(ctypes.c_void_p(ctypes.addressof(self.illldb_ptr)))
            self._runtime_loaded_fired = True
            trace_cat('bpmd', f"RuntimeLoaded callback HR=0x{int(hr) & 0xFFFFFFFF:08x}")
        except Exception as ex:
            trace(f"[invoke] runtime-loaded-cb error: {ex}")

    # --- IMemoryService ---
    def read_virtual(self, this_ptr, address, buffer, bytes_requested, bytes_read_ptr):
        try:
            trace_cat('read', f"read_virtual enter addr=0x{int(address):x} size={int(bytes_requested)}")
        except Exception:
            trace_cat('read', "read_virtual enter")
        total_read = 0
        try:
            inferior = gdb.selected_inferior()
            page_size = 4096
            remaining = int(bytes_requested)
            dest_addr = buffer if isinstance(buffer, int) else ctypes.cast(buffer, ctypes.c_void_p).value
            cur_addr = int(address)
            while remaining > 0:
                # Read up to the next page boundary to avoid crossing into unmapped pages
                to_page = page_size - (cur_addr % page_size)
                chunk_size = min(remaining, to_page)
                # Try decreasing chunk sizes on failure
                while chunk_size > 0:
                    try:
                        chunk = inferior.read_memory(cur_addr, chunk_size)
                        data = chunk.tobytes()
                        if data:
                            ctypes.memmove(dest_addr + total_read, data, len(data))
                            total_read += len(data)
                            cur_addr += len(data)
                            remaining -= len(data)
                        break
                    except gdb.MemoryError:
                        # Reduce chunk and retry within this page
                        if chunk_size == 1:
                            chunk_size = 0
                        else:
                            chunk_size = max(1, chunk_size // 2)
                if chunk_size == 0:
                    # Could not read even a single byte at this address; advance to next page
                    next_page = ((cur_addr // page_size) + 1) * page_size
                    if next_page <= cur_addr:
                        break
                    skip = next_page - cur_addr
                    cur_addr = next_page
                    if skip > remaining:
                        break
                    remaining -= skip
            if bytes_read_ptr:
                bytes_read_ptr.contents.value = total_read
            try:
                if total_read > 0:
                    trace_cat('read', f"read_virtual OK bytes={total_read}")
                else:
                    trace_cat('read', f"read_virtual FAIL bytes={total_read}")
            except Exception:
                pass
            return 0 if total_read > 0 else 0x80070005
        except Exception:
            if bytes_read_ptr:
                bytes_read_ptr.contents.value = total_read
            try:
                trace_cat('read', f"read_virtual EXCEPTION bytes={total_read}")
            except Exception:
                pass
            return 0x80070005

    # --- IHost ---
    def host_get_host_type(self, this_ptr):
        trace("call into host_get_host_type")
        return 0

    def host_get_service(self, this_ptr, guid_ptr, out_ptr):
        trace("call into host_get_service")
        if out_ptr:
            out_ptr.contents.value = 0

        if guid_ptr:
            iid = guid_ptr.contents
            if self._guid_equal(iid, IID_ILLDBServices):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.illldb_ptr)
                self.add_ref(this_ptr)
                return 0
            if self._guid_equal(iid, IID_ILLDBServices2):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.illldb2_ptr)
                self.add_ref(this_ptr)
                return 0
            if self._guid_equal(iid, IID_IHostServices):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.ihostservices_ptr)
                self.add_ref(this_ptr)
                return 0
            if self._guid_equal(iid, IID_IDebuggerServices):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.idebugger_ptr)
                self.add_ref(this_ptr)
                return 0
            if self._guid_equal(iid, IID_IMemoryService):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self.imemory_ptr)
                self.add_ref(this_ptr)
                return 0

        return 0x80004002

    def host_get_current_target(self, this_ptr, out_ptr):
        trace("call into host_get_current_target")
        try:
            if out_ptr:
                out_ptr.contents.value = ctypes.addressof(self.itarget_ptr)
            # AddRef via our owning object (harmless for SOS expectations)
            self.add_ref(this_ptr)
            return 0
        except Exception:
            if out_ptr:
                out_ptr.contents.value = 0
            return 0x80004005

    # --- ITarget (native) ---
    def target_get_operating_system(self, this_ptr):
        # ITarget.OperatingSystem enum: Unknown=0, Windows=1, Linux=2, OSX=3
        return 2  # Linux

    def target_get_service(self, this_ptr, guid_ptr, out_ptr):
        # No per-target native services yet; return E_NOINTERFACE
        try:
            if out_ptr:
                out_ptr.contents.value = 0
        except Exception:
            pass
        return 0x80004002

    # --- Helpers to notify managed host (bridge) ---
    def _update_host_target_pid_if_possible(self):
        """Invoke bridge UpdateManagedTarget(pid) if wired by sos.py and PID is known."""
        try:
            fn = getattr(self, "_bridge_update_fn", None)
            if not fn or not callable(fn):
                return
            pid = self._get_pid() or 0
            if not pid:
                return
            try:
                hr = int(fn(int(pid)))
                trace_cat('bpmd', f"[update] UpdateManagedTarget(pid={pid}) => 0x{hr & 0xFFFFFFFF:08x}")
            except Exception as ex:
                trace(f"[update] UpdateManagedTarget error: {ex}")
        except Exception as ex:
            trace(f"_update_host_target_pid_if_possible error: {ex}")

    def target_get_runtime(self, this_ptr, out_runtime_ptr):
        # Provide a minimal runtime once CoreCLR maps; SOS uses it to locate DAC and query sizes.
        path, base = self._scan_coreclr()
        try:
            if out_runtime_ptr:
                if not path or base is None:
                    out_runtime_ptr.contents.value = 0
                    return 0x80004005
                # Precompute module size if not cached
                if not self._coreclr_size:
                    self._coreclr_size = self._compute_module_size(path)
                out_runtime_ptr.contents.value = ctypes.addressof(self.iruntime_ptr)
                # AddRef via host object
                self.add_ref(this_ptr)
                return 0
        except Exception:
            pass
        return 0x80004005

    def target_flush(self, this_ptr):
        # Clear caches related to module/thread state
        try:
            self._context_cache.clear()
        except Exception:
            pass
        try:
            self._coreclr_size = 0
        except Exception:
            pass

    # --- IRuntime (native) ---
    def _compute_module_size(self, path: str) -> int:
        pid = self._get_pid()
        if not pid:
            return 0
        min_start = None
        max_end = None
        try:
            maps_path = f"/proc/{pid}/maps"
            with open(maps_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if path not in line:
                        continue
                    parts = line.strip().split()
                    if len(parts) < 6:
                        continue
                    p = ' '.join(parts[5:])
                    if p.endswith(' (deleted)'):
                        p = p[:-10]
                    if p != path:
                        continue
                    try:
                        start_str, end_str = parts[0].split('-')
                        start = int(start_str, 16)
                        end = int(end_str, 16)
                    except Exception:
                        continue
                    if min_start is None or start < min_start:
                        min_start = start
                    if max_end is None or end > max_end:
                        max_end = end
        except Exception as ex:
            trace(f"_compute_module_size error: {ex}")
        if min_start is None or max_end is None or max_end <= min_start:
            return 0
        return max_end - min_start

    def runtime_get_config(self, this_ptr):
        return int(self._runtime_config)

    def runtime_get_module_address(self, this_ptr):
        return ctypes.c_uint64(self._coreclr_base or 0).value if hasattr(self, '_coreclr_base') else ctypes.c_uint64(self._coreclr_base or 0).value

    def runtime_get_module_size(self, this_ptr):
        if not self._coreclr_size:
            path, base = self._scan_coreclr()
            if path and base is not None:
                self._coreclr_size = self._compute_module_size(path)
        return ctypes.c_uint64(self._coreclr_size or 0).value

    def runtime_set_runtime_directory(self, this_ptr, dir_ptr):
        try:
            self._runtime_dir_override = dir_ptr.decode() if isinstance(dir_ptr, bytes) else ctypes.cast(dir_ptr, ctypes.c_char_p).value.decode() if dir_ptr else None
        except Exception:
            self._runtime_dir_override = None

    def runtime_get_runtime_directory(self, this_ptr):
        # Prefer override, else from _scan_coreclr
        try:
            if self._runtime_dir_override:
                return ctypes.c_char_p(self._runtime_dir_override.encode('utf-8'))
            if self._coreclr_dir_buf is not None:
                return ctypes.cast(self._coreclr_dir_buf, ctypes.c_char_p)
            # attempt a refresh
            path, base = self._scan_coreclr()
            if self._coreclr_dir_buf is not None:
                return ctypes.cast(self._coreclr_dir_buf, ctypes.c_char_p)
        except Exception:
            pass
        return ctypes.c_char_p(None)

    def runtime_get_clr_data_process(self, this_ptr, flags, out_pp):
        # Create or return the IXCLRDataProcess instance via DAC
        try:
            if out_pp:
                out_pp.contents.value = 0
            # Return cached instance if available
            if self._clrdata_process:
                if out_pp:
                    out_pp.contents.value = self._clrdata_process
                return 0
            # Ensure runtime directory is known
            dir_c = self.runtime_get_runtime_directory(this_ptr)
            runtime_dir = None
            try:
                runtime_dir = ctypes.cast(dir_c, ctypes.c_char_p).value.decode() if dir_c else None
            except Exception:
                runtime_dir = None
            if not runtime_dir:
                # Try scanning coreclr path
                path, _ = self._scan_coreclr()
                if path:
                    runtime_dir = os.path.dirname(path)
            if not runtime_dir:
                return 0x80004005
            # Do not set or modify any environment variables here to avoid
            # triggering PAL getenv paths during DAC initialization.
            # Build DAC path
            dac_name = 'libmscordaccore.so'
            dac_path = os.path.join(runtime_dir, dac_name)
            # Load DAC
            if self._dac_handle is None:
                try:
                    # Use RTLD_GLOBAL if available so DAC can resolve to process symbols
                    mode = getattr(ctypes, 'RTLD_GLOBAL', None)
                    self._dac_handle = ctypes.CDLL(dac_path, mode=mode) if mode is not None else ctypes.CDLL(dac_path)
                except Exception as ex:
                    trace(f"[dac] load error: {ex} (path={dac_path})")
                    return 0x80004005
            # Resolve CLRDataCreateInstance
            try:
                cdi = getattr(self._dac_handle, 'CLRDataCreateInstance')
            except Exception:
                trace("[dac] CLRDataCreateInstance not found")
                return 0x80004005
            cdi.argtypes = [ctypes.POINTER(GUID), PVOID, ctypes.POINTER(PVOID)]
            cdi.restype = HRESULT
            # Prepare IID_IXCLRDataProcess
            iid = IID_IXCLRDataProcess
            # Pass our ICLRDataTarget2 pointer as legacy target
            out_iface = PVOID()
            # Ensure target has up-to-date base
            path, base = self._scan_coreclr()
            if base is None:
                return 0x80004005
            # Call CLRDataCreateInstance
            target_ptr = ctypes.cast(ctypes.byref(self._dt_ptr), ctypes.c_void_p)
            # Call CLRDataCreateInstance inline (no timeout or threading so hangs are observable for investigation)
            trace('[dac] CLRDataCreateInstance inline (no timeout)')
            hr = cdi(ctypes.byref(iid), target_ptr, ctypes.byref(out_iface))
            out_val = out_iface.value
            if hr != 0 or not out_val:
                trace(f"[dac] CLRDataCreateInstance failed hr=0x{hr & 0xFFFFFFFF:08x}")
                return hr if hr != 0 else 0x80004005
            # Cache and return
            self._clrdata_process = out_val
            if out_pp:
                out_pp.contents.value = self._clrdata_process
            trace("[dac] IXCLRDataProcess created")
            return 0
        except Exception as ex:
            trace(f"runtime_get_clr_data_process error: {ex}")
            try:
                if out_pp:
                    out_pp.contents.value = 0
            except Exception:
                pass
            return 0x80004005

    # ---- ICLRDataTarget2 implementation ----
    def _dt_query_interface(self, this_ptr, iid_ptr, out_ptr):
        try:
            iid = iid_ptr.contents if iid_ptr else None
            if out_ptr:
                out_ptr.contents.value = 0
            if iid is None:
                return 0x80004003
            if self._guid_equal(iid, IID_IUnknown) or self._guid_equal(iid, IID_ICLRDataTarget) or self._guid_equal(iid, IID_ICLRDataTarget2):
                if out_ptr:
                    out_ptr.contents.value = ctypes.addressof(self._dt_ptr)
                self._dt_add_ref(this_ptr)
                return 0
            return 0x80004002
        except Exception:
            return 0x80004005

    def _dt_add_ref(self, this_ptr):
        try:
            self._dt_ref += 1
            return self._dt_ref
        except Exception:
            return 1

    def _dt_release(self, this_ptr):
        try:
            self._dt_ref = max(0, self._dt_ref - 1)
            return self._dt_ref
        except Exception:
            return 0

    def _dt_get_machine_type(self, this_ptr, machine_ptr):
        try:
            if machine_ptr:
                machine_ptr.contents.value = self._detect_machine_type()
            return 0
        except Exception:
            return 0x80004005

    def _dt_get_pointer_size(self, this_ptr, size_ptr):
        try:
            if size_ptr:
                size_ptr.contents.value = self._detect_pointer_size()
            return 0
        except Exception:
            return 0x80004005

    def _dt_get_image_base(self, this_ptr, name_w, base_ptr):
        # Return coreclr base when the module name matches; otherwise E_FAIL
        try:
            if not base_ptr:
                return 0x80004003
            path, base = self._scan_coreclr()
            if base is None:
                return 0x80004005
            # name_w is LPCWSTR; normalize to Python str
            name = None
            try:
                if isinstance(name_w, str):
                    name = name_w
                elif name_w is not None:
                    name = ctypes.cast(name_w, ctypes.c_wchar_p).value
            except Exception:
                name = None
            if not name:
                return 0x80004005
            bn = self._canon_modname(name)
            if bn in ("coreclr", "libcoreclr"):
                base_ptr.contents.value = ctypes.c_uint64(base).value
                return 0
            return 0x80004005
        except Exception:
            return 0x80004005

    def _dt_read_virtual(self, this_ptr, address, buffer, request, done_ptr):
        # Prefer direct process_vm_readv to avoid re-entering GDB during DAC init
        total = 0
        try:
            try:
                trace_cat('read', f"_dt_read_virtual enter addr=0x{int(address):x} size={int(request)}")
            except Exception:
                pass
            if not buffer or request <= 0:
                if done_ptr:
                    done_ptr.contents.value = 0
                return 0
            pid = self._get_pid() or 0
            if pid:
                # libc.process_vm_readv
                try:
                    if not hasattr(self, "_libc_handle"):
                        self._libc_handle = ctypes.CDLL("libc.so.6")
                    libc = self._libc_handle
                    class IOVec(ctypes.Structure):
                        _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]
                    local = IOVec()
                    remote = IOVec()
                    dst = buffer if isinstance(buffer, int) else ctypes.cast(buffer, ctypes.c_void_p).value
                    local.iov_base = ctypes.c_void_p(dst)
                    local.iov_len = ctypes.c_size_t(int(request))
                    remote.iov_base = ctypes.c_void_p(int(address))
                    remote.iov_len = ctypes.c_size_t(int(request))
                    process_vm_readv = getattr(libc, 'process_vm_readv')
                    process_vm_readv.argtypes = [ctypes.c_int, ctypes.POINTER(IOVec), ctypes.c_ulong, ctypes.POINTER(IOVec), ctypes.c_ulong, ctypes.c_ulong]
                    process_vm_readv.restype = ctypes.c_ssize_t
                    n = process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
                    if n and n > 0:
                        total = int(n)
                        try:
                            trace_cat('read', f"_dt_read_virtual pv_readv OK bytes={total}")
                        except Exception:
                            pass
                except Exception:
                    total = 0
            if total == 0:
                # Fallback to GDB API in paged chunks
                try:
                    trace_cat('read', "_dt_read_virtual fallback to gdb.read_virtual")
                except Exception:
                    pass
                return self.read_virtual(this_ptr, address, buffer, request, done_ptr)
            if done_ptr:
                done_ptr.contents.value = total
            try:
                trace_cat('read', f"_dt_read_virtual OK bytes={total}")
            except Exception:
                pass
            return 0
        except Exception:
            if done_ptr:
                done_ptr.contents.value = total
            try:
                trace_cat('read', f"_dt_read_virtual EXCEPTION bytes={total}")
            except Exception:
                pass
            return 0x80070005

    def _dt_write_virtual(self, this_ptr, address, buffer, request, done_ptr):
        # Implement ICLRDataTarget2::WriteVirtual so DAC can update target memory (e.g., JIT notification tables)
        total = 0
        try:
            try:
                trace_cat('write', f"_dt_write_virtual enter addr=0x{int(address):x} size={int(request)}")
            except Exception:
                pass
            # Validate args
            if not buffer or not request or request <= 0:
                if done_ptr:
                    try:
                        done_ptr.contents.value = 0
                    except Exception:
                        pass
                try:
                    trace_cat('write', "_dt_write_virtual zero-len or null buffer => OK(0)")
                except Exception:
                    pass
                return 0

            # Do not allow writes in core dump sessions
            try:
                if self._is_core_dump_session():
                    if done_ptr:
                        try:
                            done_ptr.contents.value = 0
                        except Exception:
                            pass
                    return 0x80004001  # E_NOTIMPL for dump analysis
            except Exception:
                # If detection fails, continue best-effort
                pass

            # Extract bytes from the provided buffer pointer
            try:
                data = ctypes.string_at(buffer, int(request))
            except Exception as ex:
                trace_cat('write', f"_dt_write_virtual string_at failed: {ex}")
                if done_ptr:
                    try:
                        done_ptr.contents.value = 0
                    except Exception:
                        pass
                return 0x80070005  # E_ACCESSDENIED

            # Prefer using gdb inferior API to write memory
            try:
                inferior = gdb.selected_inferior()
                inferior.write_memory(int(address), data)
                total = int(request)
            except Exception as ex:
                trace_cat('write', f"_dt_write_virtual gdb write_memory failed: {ex}")
                total = 0

            if done_ptr:
                try:
                    done_ptr.contents.value = total
                except Exception:
                    pass
            try:
                if total == int(request):
                    trace_cat('write', f"_dt_write_virtual OK bytes={total}")
                else:
                    trace_cat('write', f"_dt_write_virtual FAIL bytes={total}")
            except Exception:
                pass
            return 0 if total == int(request) else 0x80070005
        except Exception as ex:
            trace_cat('write', f"_dt_write_virtual EXCEPTION: {ex}")
            if done_ptr:
                try:
                    done_ptr.contents.value = total
                except Exception:
                    pass
            return 0x80070005

    def _dt_get_tls_value(self, this_ptr, threadID, index, value_ptr):
        return 0x80004001

    def _dt_set_tls_value(self, this_ptr, threadID, index, value):
        return 0x80004001

    def _dt_get_current_thread_id(self, this_ptr, threadID_ptr):
        try:
            if threadID_ptr:
                # Map to the current system thread id
                cur = gdb.selected_thread()
                sysid = self._thread_sysid(cur) if cur else 0
                threadID_ptr.contents.value = sysid
            return 0
        except Exception:
            return 0x80004005

    def _dt_get_thread_context(self, this_ptr, threadID, contextFlags, contextSize, context):
        try:
            return self.lldb_get_thread_context_by_system_id(this_ptr, threadID, contextFlags, contextSize, context)
        except Exception:
            return 0x80004005

    def _dt_set_thread_context(self, this_ptr, threadID, contextSize, context):
        return 0x80004001

    def _dt_request(self, this_ptr, reqCode, inSize, inBuffer, outSize, outBuffer):
        return 0x80004001

    def _dt_alloc_virtual(self, this_ptr, addr, size, typeFlags, protectFlags, virt_ptr):
        return 0x80004001

    def _dt_free_virtual(self, this_ptr, addr, size, typeFlags):
        return 0x80004001

    def runtime_get_cordebug_interface(self, this_ptr, out_pp):
        # Not supported in GDB flow
        try:
            if out_pp:
                out_pp.contents.value = 0
        except Exception:
            pass
        return 0x80004002

    def runtime_get_ee_version(self, this_ptr, pFileInfo, buf, bufSize):
        # Optional; return E_NOTIMPL for now
        return 0x80004001

    # --- IHostServices ---
    def hostservices_get_host(self, this_ptr, ppHost):
        trace("call into hostservices_get_host")
        if ppHost:
            ppHost.contents.value = ctypes.addressof(self.ihost_ptr)
        return 0

    def hostservices_register_debugger_services(self, this_ptr, iunk):
        trace("call into hostservices_register_debugger_services")
        self._registered_debugger = iunk
        return 0

    def hostservices_create_target(self, this_ptr):
        trace("call into hostservices_create_target")
        return 0

    def hostservices_update_target(self, this_ptr, processId):
        trace(f"call into hostservices_update_target pid={processId}")
        return 0

    def hostservices_flush_target(self, this_ptr):
        trace("call into hostservices_flush_target")

    def hostservices_destroy_target(self, this_ptr):
        trace("call into hostservices_destroy_target")

    def hostservices_dispatch_command(self, this_ptr, commandName, arguments, displayCommandNotFound):
        try:
            cn = commandName.decode() if commandName else None
            args = arguments.decode() if arguments else None
            trace(f"call into hostservices_dispatch_command cmd={cn} args={args} displayCNF={bool(displayCommandNotFound)}")
        except Exception:
            trace("call into hostservices_dispatch_command")
        return 0x80004001

    def hostservices_uninitialize(self, this_ptr):
        trace("call into hostservices_uninitialize")

    # --- ILLDBServices2 ---
    def lldb2_load_native_symbols(self, this_ptr, runtimeOnly, callback):
        trace("call into lldb2_load_native_symbols")
        return 0

    def lldb2_add_module_symbol(self, this_ptr, param, symbolFilePath):
        trace("call into lldb2_add_module_symbol")
        return 0

    def lldb2_get_module_info(self, this_ptr, index, moduleBase, moduleSize, timestamp, checksum):
        trace(f"call into lldb2_get_module_info index={index}")
        if index != 0:
            return 0x80004005
        path, base_addr = self._scan_coreclr()
        if not path or base_addr is None:
            return 0x80004005
        pid = self._get_pid()
        min_start = None
        max_end = None
        try:
            if pid:
                maps_path = f"/proc/{pid}/maps"
                with open(maps_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if 'libcoreclr.so' not in line:
                            continue
                        parts = line.strip().split()
                        if len(parts) < 6:
                            continue
                        p = ' '.join(parts[5:])
                        if p.endswith(' (deleted)'):
                            p = p[:-10]
                        if not p.startswith('/'):
                            continue
                        if p != path:
                            continue
                        try:
                            start_str, end_str = parts[0].split('-')
                            start = int(start_str, 16)
                            end = int(end_str, 16)
                        except Exception:
                            continue
                        if min_start is None or start < min_start:
                            min_start = start
                        if max_end is None or end > max_end:
                            max_end = end
        except Exception as ex:
            trace(f"GetModuleInfo maps scan error: {ex}")

        size_val = 0
        if min_start is not None and max_end is not None and max_end > min_start:
            size_val = max_end - min_start

        if moduleBase:
            moduleBase.contents.value = ctypes.c_uint64(base_addr).value
        if moduleSize:
            moduleSize.contents.value = ctypes.c_uint64(size_val).value
        if timestamp:
            timestamp.contents.value = 0
        if checksum:
            checksum.contents.value = 0
        trace(f"  -> base=0x{base_addr:x} size=0x{size_val:x}")
        return 0

    def lldb2_get_module_version_information(self, this_ptr, index, base, item, buffer, bufferSize, versionInfoSize):
        trace("call into lldb2_get_module_version_information")
        return 0x80004001

    def lldb2_set_runtime_loaded_callback(self, this_ptr, callback):
        trace_cat('bpmd', 'call into lldb2_set_runtime_loaded_callback')
        try:
            # Save the callback pointer
            self._runtime_loaded_cb = callback
            trace_cat('bpmd', 'runtime-loaded cb registered')

            # If a breakpoint already exists, keep it
            if self._runtime_loaded_bp is not None:
                return 0

            # Ensure pending breakpoints are allowed so the bp binds when coreclr loads
            try:
                gdb.execute('set breakpoint pending on', to_string=True)
            except Exception:
                pass

            services_self = self

            # Define a Python breakpoint that invokes the callback and continues execution
            class _RuntimeLoadedBP(gdb.Breakpoint):
                def stop(self_inner):
                    try:
                        # Mark runtime initialized when the entry is reached
                        services_self._runtime_initialized = True
                        # Refresh coreclr mapping cache and update host target PID
                        try:
                            services_self._scan_coreclr()
                        except Exception:
                            pass
                        try:
                            services_self._update_host_target_pid_if_possible()
                        except Exception:
                            pass
                        # Cast callback and call with ILLDBServices* once if not already fired
                        if services_self._runtime_loaded_cb and not services_self._runtime_loaded_fired:
                            CBTYPE = ctypes.CFUNCTYPE(HRESULT, ctypes.c_void_p)
                            cb = ctypes.cast(services_self._runtime_loaded_cb, CBTYPE)
                            hr = cb(ctypes.c_void_p(ctypes.addressof(services_self.illldb_ptr)))
                            h = int(hr) & 0xFFFFFFFF
                            trace_cat('bpmd', f"RuntimeLoaded callback HR=0x{h:08x}")
                            if h == 0:
                                services_self._runtime_loaded_fired = True
                    except Exception as ex:
                        trace_cat('bpmd', f"RuntimeLoaded callback error: {ex}")
                    # Auto-continue after calling the runtime-loaded callback to mirror LLDB behavior
                    return False

            # Listen for lib loads in case symbol binding is delayed
            if not self._newobj_hook_registered:
                try:
                    gdb.events.new_objfile.connect(self._newobj_handler)
                    self._newobj_hook_registered = True
                    trace("[new-objfile] connected")
                except Exception as ex:
                    trace(f"[new-objfile] connect error: {ex}")
            # Create a pending breakpoint on the runtime entrypoint as a fallback
            # but avoid duplicating if one already exists.
            try:
                existing = False
                try:
                    for bp in (gdb.breakpoints() or []):
                        loc = getattr(bp, 'location', '') or ''
                        if 'coreclr_execute_assembly' in loc:
                            existing = True
                            break
                except Exception:
                    existing = False
                if existing:
                    trace('[runtime-bp] skip: coreclr_execute_assembly breakpoint already exists')
                else:
                    self._runtime_loaded_bp = _RuntimeLoadedBP('coreclr_execute_assembly', temporary=True)
                    try:
                        self._runtime_loaded_bp.silent = True
                    except Exception:
                        pass
            except Exception:
                # Fallback to command if constructor fails
                try:
                    gdb.execute('tbreak coreclr_execute_assembly', to_string=True)
                except Exception as ex2:
                    trace_cat('bpmd', f"[runtime-bp] failed to set fallback bp: {ex2}")
            return 0
        except Exception as ex:
            trace(f"lldb2_set_runtime_loaded_callback error: {ex}")
            return 0x80004005

    # --- ILLDBServices ---
    def lldb_get_coreclr_directory(self, this_ptr):
        trace("call into lldb_get_coreclr_directory")
        try:
            # Expose CoreCLR directory as soon as libcoreclr.so is mapped.
            # Do not strictly gate on runtime entry; LLDB returns the path
            # whenever the module is present, and SOS may query this early.
            path, base = self._scan_coreclr()
            if path and self._coreclr_dir_buf:
                trace(f"coreclr directory: {os.path.dirname(path)} base=0x{base:x}")
                return ctypes.cast(self._coreclr_dir_buf, ctypes.c_char_p)
        except Exception as ex:
            trace(f"lldb_get_coreclr_directory error: {ex}")
        trace("coreclr directory: NOT FOUND")
        return None

    def lldb_get_expression(self, this_ptr, exp):
        trace("call into lldb_get_expression")
        try:
            expr = exp.decode() if isinstance(exp, (bytes, bytearray)) else exp
            val = gdb.parse_and_eval(expr)
            try:
                return int(val)
            except Exception:
                try:
                    return int(val.cast(gdb.lookup_type('unsigned long long')))
                except Exception:
                    return 0
        except Exception:
            return 0

    def lldb_virtual_unwind(self, this_ptr, threadID, contextSize, context):
        trace("call into lldb_virtual_unwind")
        # For now return S_OK without modifying context; SOS may still walk managed frames using its own unwinder
        return 0

    def lldb_set_exception_callback(self, this_ptr, cb):
        trace_cat('bpmd', 'call into lldb_set_exception_callback')
        try:
            self._exception_cb = cb
            trace_cat('bpmd', 'exception cb registered')
            # Ensure pending breakpoints allowed
            try:
                gdb.execute('set breakpoint pending on', to_string=True)
            except Exception:
                pass
            # Install persistent, silent Python breakpoints on __cxa_throw and __cxa_rethrow
            # to mirror LLDB's exception breakpoint behavior without CLI 'Catchpoint' output.
            try:
                if not getattr(self, '_cpp_exception_bps', None):
                    services_self = self

                    class _CppExceptionBP(gdb.Breakpoint):
                        def __init__(bp_self, loc: str):
                            super().__init__(loc, temporary=False)
                            try:
                                bp_self.silent = True
                            except Exception:
                                pass

                        def stop(bp_self):
                            try:
                                # Assume runtime is already loaded when exception callback is registered
                                if not getattr(services_self, '_exception_cb', None):
                                    return False
                                ETYPE = ctypes.CFUNCTYPE(HRESULT, ctypes.c_void_p)
                                ecb = ctypes.cast(services_self._exception_cb, ETYPE)
                                hr = ecb(ctypes.c_void_p(ctypes.addressof(services_self.illldb_ptr)))
                                trace_cat('bpmd', f"[exception-bp] Exception callback HR=0x{int(hr) & 0xFFFFFFFF:08x}")
                            except Exception as ex:
                                trace_cat('bpmd', f"[exception-bp] callback error: {ex}")
                            # TEMP: disable auto-continue to diagnose run-state/race; leave a clear trace
                            trace_cat('bpmd', "[exception-bp] auto-continue suppressed for diagnostics")
                            return False

                    bps = []
                    # Create pending breakpoints; they will resolve when libstdc++ is loaded
                    try:
                        bps.append(_CppExceptionBP('__cxa_throw'))
                        trace_cat('bpmd', "[exception-bp] installed '__cxa_throw' breakpoint")
                    except Exception as ex_t:
                        trace_cat('bpmd', f"[exception-bp] failed to set __cxa_throw: {ex_t}")
                    try:
                        bps.append(_CppExceptionBP('__cxa_rethrow'))
                        trace_cat('bpmd', "[exception-bp] installed '__cxa_rethrow' breakpoint")
                    except Exception as ex_r:
                        trace_cat('bpmd', f"[exception-bp] failed to set __cxa_rethrow: {ex_r}")

                    self._cpp_exception_bps = [bp for bp in bps if bp is not None]
                    if not self._cpp_exception_bps:
                        trace_cat('bpmd', "[exception-bp] warning: no exception symbol breakpoints installed")
            except Exception as ex:
                trace(f"[exception-bp] install error: {ex}")

            # Connect new-objfile hook to catch when CoreCLR loads later
            if not self._newobj_hook_registered:
                try:
                    gdb.events.new_objfile.connect(self._newobj_handler)
                    self._newobj_hook_registered = True
                    trace("[new-objfile] connected")
                except Exception as ex:
                    trace(f"[new-objfile] connect error: {ex}")
            # Connect stop hook to drive callback and auto-continue on C++ throw stops
            if not getattr(self, '_stop_hook_registered', False):
                try:
                    gdb.events.stop.connect(self._stop_handler)
                    self._stop_hook_registered = True
                    trace_cat('bpmd', "[stop-hook] connected")
                except Exception as ex:
                    trace_cat('bpmd', f"[stop-hook] connect error: {ex}")
            return 0
        except Exception:
            return 0x80004005

    def lldb_clear_exception_callback(self, this_ptr):
        trace("call into lldb_clear_exception_callback")
        self._exception_cb = None
        # Remove C++ exception symbol breakpoints if we created them
        try:
            bps = getattr(self, '_cpp_exception_bps', None)
            if bps:
                for bp in list(bps):
                    try:
                        if bp is not None:
                            bp.delete()
                    except Exception:
                        pass
                self._cpp_exception_bps = []
                trace("[exception-bp] removed __cxa_throw/__cxa_rethrow breakpoints")
        except Exception as ex:
            trace(f"[exception-bp] remove error: {ex}")
        # Disconnect the stop hook if connected
        if self._stop_hook_registered:
            try:
                gdb.events.stop.disconnect(self._stop_handler)
                self._stop_hook_registered = False
                trace("[stop-hook] disconnected")
            except Exception as ex:
                trace(f"[stop-hook] disconnect error: {ex}")
        # Disconnect new-objfile hook if connected
        if self._newobj_hook_registered:
            try:
                gdb.events.new_objfile.disconnect(self._newobj_handler)
                self._newobj_hook_registered = False
                trace("[new-objfile] disconnected")
            except Exception as ex:
                trace(f"[new-objfile] disconnect error: {ex}")
        return 0

    def lldb_get_interrupt(self, this_ptr):
        trace("call into lldb_get_interrupt")
        # Return S_OK (0) when interrupted, S_FALSE (1) otherwise
        return 0 if getattr(self, "_interrupted", False) else 1

    def lldb_output_va_list(self, this_ptr, mask, fmt, va_list_ptr):
        trace("call into lldb_output_va_list")
        try:
            if getattr(self, "_interrupted", False):
                return 0
            libc = getattr(self, "_libc_handle", None)
            if libc is None:
                try:
                    libc = ctypes.CDLL("libc.so.6")
                except Exception:
                    libc = ctypes.CDLL(None)
                self._libc_handle = libc
            vsnprintf = getattr(self, "_vsnprintf_func", None)
            if vsnprintf is None:
                vsnprintf = libc.vsnprintf
                vsnprintf.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_void_p]
                vsnprintf.restype = ctypes.c_int
                self._vsnprintf_func = vsnprintf
            size = 1024
            while True:
                buf = ctypes.create_string_buffer(size)
                written = vsnprintf(buf, size, fmt, va_list_ptr)
                if written < 0:
                    break
                if written >= size:
                    size = written + 1
                    buf = ctypes.create_string_buffer(size)
                    vsnprintf(buf, size, fmt, va_list_ptr)
                try:
                    gdb.write(buf.value.decode(errors='replace'))
                except Exception:
                    try:
                        import sys as _sys
                        _sys.stdout.write(buf.value.decode(errors='replace'))
                    except KeyboardInterrupt:
                        self._interrupted = True
                        return 0
                    except Exception:
                        pass
                break
        except KeyboardInterrupt:
            self._interrupted = True
        except Exception:
            pass
        return 0

    def lldb_get_debuggee_type(self, this_ptr, debugClass, qualifier):
        trace("call into lldb_get_debuggee_type")
        # Report live user-mode for normal runs (including pre-run), but detect real
        # core dump sessions via 'info files' so dump analysis still works.
        if debugClass:
            debugClass.contents.value = DEBUG_CLASS_USER_WINDOWS
        if qualifier:
            try:
                is_core = self._is_core_dump_session()
            except Exception:
                is_core = False
            qualifier.contents.value = DEBUG_DUMP_FULL if is_core else 0
        return 0

    def lldb_get_page_size(self, this_ptr, size_ptr):
        trace("call into lldb_get_page_size")
        if size_ptr:
            size_ptr.contents.value = 4096
        return 0

    def lldb_get_processor_type(self, this_ptr, type_ptr):
        trace("call into lldb_get_processor_type")
        if type_ptr:
            try:
                type_ptr.contents.value = self._detect_machine_type()
            except Exception:
                # Default to AMD64 if detection fails
                type_ptr.contents.value = IMAGE_FILE_MACHINE_AMD64
        return 0

    def lldb_execute(self, this_ptr, outctl, command, flags):
        trace("call into lldb_execute")
        try:
            cmd = command.decode() if command else ""
            if cmd and TRACE_ENABLED:
                low = (cmd or '').strip().lower()
                if low.startswith('breakpoint set') or low.startswith('process continue'):
                    gdb.write(f"[ILLDBServices.Execute] {cmd}\n")
            # Map a minimal subset of LLDB host commands used by SOS to GDB
            text = (cmd or '').strip()
            lower = text.lower()
            # 0) process continue => schedule a GDB continue safely
            if lower == 'process continue' or lower.startswith('process continue'):
                # Only guard against duplicate pending continues; allow from callbacks.
                try:
                    if getattr(self, '_continue_pending', False):
                        trace('[execute] continue suppressed: continue already pending')
                        return 1  # S_FALSE
                except Exception:
                    pass
                self._schedule_safe_continue()
                return 0
            # 1) breakpoint set --address 0xADDR => break *0xADDR
            if lower.startswith('breakpoint set') and '--address' in lower:
                try:
                    # Extract the token after --address (allow '=' or space)
                    import re as _re
                    m = _re.search(r"--address(?:=|\s+)(0x[0-9a-fA-F]+|[0-9]+)", text)
                    if m:
                        addr = m.group(1)
                        gdb.execute(f"break *{addr}", to_string=True)
                    else:
                        trace("[execute] could not parse address for breakpoint set")
                except Exception as ex:
                    trace(f"[execute] breakpoint set --address error: {ex}")
                return 0
            # 2) breakpoint set --name SYMBOL => break SYMBOL
            if lower.startswith('breakpoint set') and '--name' in lower:
                try:
                    import re as _re
                    m = _re.search(r"--name(?:=|\s+)([^\s]+)", text)
                    if m:
                        sym = m.group(1)
                        gdb.execute(f"break {sym}", to_string=True)
                    else:
                        trace("[execute] could not parse name for breakpoint set")
                except Exception as ex:
                    trace(f"[execute] breakpoint set --name error: {ex}")
                return 0
        except Exception:
            pass
        return 0

    def lldb_get_last_event_information(self, this_ptr, t, pid, tid, extra, extraSize, extraUsed, desc, descSize, descUsed):
        trace("call into lldb_get_last_event_information")
        if t: t.contents.value = 0
        if pid: pid.contents.value = 0
        if tid: tid.contents.value = 0
        if extraUsed: extraUsed.contents.value = 0
        if descUsed: descUsed.contents.value = 0
        return 0

    def lldb_disassemble(self, this_ptr, offset, flags, buffer, bufferSize, disSize, endOffset):
        trace("call into lldb_disassemble")
        # Never hang the caller. Best-effort decode 1 instruction and advance endOffset.
        try:
            try:
                trace_cat('disasm', f"[disasm] request addr=0x{int(offset):x}")
            except Exception:
                pass

            text = None
            adv = 1
            faddr = int(offset)
            saved_flavor = None

            # Save and temporarily switch to Intel flavor to avoid '%' registers (printf hazards)
            try:
                show = gdb.execute("show disassembly-flavor", to_string=True)
                low = (show or "").lower()
                if "intel" in low:
                    saved_flavor = "intel"
                elif "att" in low:
                    saved_flavor = "att"
                else:
                    saved_flavor = None
            except Exception:
                saved_flavor = None
            try:
                if saved_flavor != "intel":
                    gdb.execute("set disassembly-flavor intel", to_string=True)
            except Exception:
                pass

            try:
                # Probe two instructions so we can compute the next address reliably
                out2 = gdb.execute(f"x/2i 0x{int(offset):x}", to_string=True)
                lines = [ln for ln in (out2 or '').splitlines() if ln.strip()]
                if lines:
                    first = lines[0].strip()
                    sec = lines[1].strip() if len(lines) > 1 else None
                    # Extract text for first instruction
                    parts = first.split('\t', 1)
                    if len(parts) == 2:
                        text = parts[1]
                    else:
                        cidx = first.find(':')
                        text = first[cidx+1:].strip() if cidx >= 0 else first
                    # Compute instruction length using numeric addresses
                    try:
                        faddr_str = first.split(':', 1)[0].strip()
                        faddr = int(faddr_str, 16) if faddr_str.startswith('0x') else int(faddr_str, 16)
                        if sec:
                            saddr_str = sec.split(':', 1)[0].strip()
                            saddr = int(saddr_str, 16) if saddr_str.startswith('0x') else int(saddr_str, 16)
                            if saddr > faddr:
                                adv = max(1, saddr - faddr)
                    except Exception:
                        adv = max(1, adv)
                else:
                    # Fallback to a single instruction
                    out1 = gdb.execute(f"x/1i 0x{int(offset):x}", to_string=True)
                    if out1:
                        line = out1.strip().splitlines()[0]
                        parts = line.split('\t', 1)
                        if len(parts) == 2:
                            text = parts[1]
                        else:
                            cidx = line.find(':')
                            text = line[cidx+1:].strip() if cidx >= 0 else line
            except Exception as ex:
                try:
                    trace_cat('disasm', f"[disasm] gdb disassemble error: {ex}")
                except Exception:
                    pass

            # Restore disassembly flavor if we changed it
            try:
                if saved_flavor and saved_flavor != "intel":
                    gdb.execute(f"set disassembly-flavor {saved_flavor}", to_string=True)
            except Exception:
                pass

            # Escape % to avoid downstream printf formatting in SOS
            if text and ("%" in text):
                try:
                    esc = text.replace('%', '%%')
                    if esc != text:
                        trace_cat('disasm', "[disasm] escaped percents in text")
                    text = esc
                except Exception:
                    pass

            # Optionally format into LLDB-like columns: address | bytes | mnemonic | operands
            # Controlled by environment variables (default off):
            #   SOS_GDB_DISASM_ADDR=1       -> include address column
            #   SOS_GDB_DISASM_BYTES=1      -> include raw bytes column (contiguous hex)
            #   SOS_GDB_DISASM_MNEMONIC_COL -> column (1-based) where mnemonic should start (default 39)
            #   SOS_GDB_DISASM_OPERAND_COL  -> column (1-based) where operands should start (default 50)
            try:
                want_addr = (os.getenv('SOS_GDB_DISASM_ADDR', '1') or '1').lower() in ('1','true','yes','on')
            except Exception:
                # Default to enabled if env read fails
                want_addr = True
            try:
                want_bytes = (os.getenv('SOS_GDB_DISASM_BYTES', '1') or '1').lower() in ('1','true','yes','on')
            except Exception:
                # Default to enabled if env read fails
                want_bytes = True

            # Canonicalize RIP displacement like "rip+0xfffffffffff85ca7" to "rip - 0x7a359"
            try:
                canonical_rip = (os.getenv('SOS_GDB_DISASM_CANONICAL_RIP', '1') or '1').lower() in ('1','true','yes','on')
            except Exception:
                canonical_rip = True
            if text and canonical_rip:
                try:
                    pattern = re.compile(r"\brip\s*\+\s*0x([0-9a-fA-F]+)\b")
                    def _rip_repl(m):
                        hx = m.group(1)
                        try:
                            val = int(hx, 16)
                            # Treat values > 2^63-1 as negative two's complement and convert to subtract form
                            if val > 0x7FFFFFFFFFFFFFFF:
                                delta = (1 << 64) - val
                                return f"rip - 0x{delta:x}"
                        except Exception:
                            pass
                        return m.group(0)
                    new_text = pattern.sub(_rip_repl, text)
                    if new_text != text:
                        try:
                            trace_cat('disasm', "[disasm] normalized RIP displacement")
                        except Exception:
                            pass
                        text = new_text
                except Exception:
                    pass

            # Compute columns only when prefix requested; otherwise keep plain text
            out_text = text
            if text is not None and (want_addr or want_bytes):
                # Load optional column positions
                try:
                    MNEMONIC_COL = max(20, int(os.getenv('SOS_GDB_DISASM_MNEMONIC_COL', '39')))
                except Exception:
                    MNEMONIC_COL = 39
                try:
                    OPERAND_COL = max(MNEMONIC_COL + 6, int(os.getenv('SOS_GDB_DISASM_OPERAND_COL', '50')))
                except Exception:
                    OPERAND_COL = max(MNEMONIC_COL + 6, 50)

                # Address and bytes strings
                addr_str = f"{faddr:016x}" if want_addr else ""
                bytes_str = ""
                if want_bytes and isinstance(faddr, int) and isinstance(adv, int) and adv > 0:
                    try:
                        inf = gdb.selected_inferior()
                        data = bytes(inf.read_memory(faddr, adv)) if inf else b''
                        if data:
                            # Contiguous lowercase hex like LLDB (e.g., 4883ec20)
                            bytes_str = data.hex()
                    except Exception:
                        bytes_str = ""

                # Split mnemonic and operands from text
                mnemonic = text
                operands = ""
                try:
                    parts = text.split(None, 1)
                    if len(parts) == 2:
                        mnemonic, operands = parts[0], parts[1]
                    elif len(parts) == 1:
                        mnemonic = parts[0]
                except Exception:
                    mnemonic, operands = text, ""

                # Build line with alignment
                line = ""
                if addr_str:
                    line += addr_str
                if bytes_str:
                    line += (" " if line else "") + bytes_str

                # Pad to mnemonic column
                if line:
                    cur_len = len(line)
                    pad = MNEMONIC_COL - cur_len
                    if pad < 2:
                        pad = 2
                    line += " " * pad

                # Add mnemonic
                line += mnemonic

                # Pad to operands column (only if we have operands)
                if operands:
                    cur_len2 = len(line)
                    pad2 = OPERAND_COL - cur_len2
                    if pad2 < 1:
                        pad2 = 1
                    line += " " * pad2 + operands

                out_text = line

            # Write text to caller's buffer
            written = 0
            try:
                if out_text and buffer and bufferSize and bufferSize > 1:
                    bs = out_text.encode('utf-8', errors='replace')
                    n = min(len(bs), max(0, int(bufferSize) - 1))
                    if n > 0:
                        dst = buffer if isinstance(buffer, int) else ctypes.cast(buffer, ctypes.c_void_p).value
                        if dst:
                            ctypes.memmove(dst, bs, n)
                            ctypes.memmove(dst + n, b"\x00", 1)
                            written = n
            except Exception:
                written = 0

            if disSize:
                try:
                    disSize.contents.value = written
                except Exception:
                    pass
            if endOffset:
                try:
                    endOffset.contents.value = ctypes.c_uint64(int(offset) + max(1, int(adv))).value
                except Exception:
                    pass

            rc = 0 if written > 0 else 1
            try:
                trace_cat('disasm', f"[disasm] wrote={written} adv={adv} rc={rc}")
            except Exception:
                pass
            return rc
        except Exception as ex:
            # On any error, indicate no text but still advance to avoid infinite loops.
            try:
                if disSize:
                    disSize.contents.value = 0
                if endOffset:
                    endOffset.contents.value = ctypes.c_uint64(int(offset) + 1).value
                trace_cat('disasm', f"[disasm] exception: {ex}")
            except Exception:
                pass
            return 1

    def lldb_get_context_stack_trace(self, this_ptr, startContext, startContextSize, frames, framesSize, frameContexts, frameContextsSize, frameContextsEntrySize, framesFilled):
        trace("call into lldb_get_context_stack_trace")
        return 0x80004001

    def lldb_read_virtual(self, this_ptr, address, buffer, bufferSize, bytesRead):
        try:
            trace_cat('read', f"lldb_read_virtual enter addr=0x{int(address):x} size={int(bufferSize)}")
        except Exception:
            pass
        return self.read_virtual(this_ptr, address, buffer, bufferSize, bytesRead)

    def lldb_write_virtual(self, this_ptr, address, buffer, bufferSize, bytesWritten):
        try:
            trace_cat('write', f"lldb_write_virtual enter addr=0x{int(address):x} size={int(bufferSize)}")
        except Exception:
            pass
        # Delegate to the same implementation as ICLRDataTarget2::WriteVirtual
        total = 0
        try:
            hr = self._dt_write_virtual(this_ptr, address, buffer, bufferSize, bytesWritten)
            # Ensure bytesWritten is set even if caller passed a distinct pointer
            if bytesWritten and (hr == 0):
                try:
                    # If _dt_write_virtual didn't update it (due to pointer mismatch), fill it here
                    if not isinstance(bytesWritten.contents.value, int) or bytesWritten.contents.value == 0:
                        bytesWritten.contents.value = int(bufferSize)
                except Exception:
                    pass
            try:
                bw = 0
                try:
                    bw = bytesWritten.contents.value if bytesWritten else 0
                except Exception:
                    bw = 0
                trace_cat('write', f"lldb_write_virtual exit hr=0x{int(hr) & 0xFFFFFFFF:08x} bytes={bw}")
            except Exception:
                pass
            return hr
        except Exception as ex:
            trace_cat('write', f"lldb_write_virtual EXCEPTION: {ex}")
            try:
                if bytesWritten:
                    bytesWritten.contents.value = 0
            except Exception:
                pass
            return 0x80070005

    def lldb_get_symbol_options(self, this_ptr, options):
        trace("call into lldb_get_symbol_options")
        return 0x80004001

    def lldb_get_name_by_offset(self, this_ptr, offset, nameBuffer, nameBufferSize, nameSize, displacement):
        trace("call into lldb_get_name_by_offset")
        return 0x80004001

    def lldb_get_number_modules(self, this_ptr, loaded, unloaded):
        trace("call into lldb_get_number_modules")
        path, _ = self._scan_coreclr()
        if loaded:
            loaded.contents.value = 1 if path else 0
        if unloaded:
            unloaded.contents.value = 0
        trace(f"  -> loaded={loaded.contents.value if loaded else 'n/a'} unloaded={unloaded.contents.value if unloaded else 'n/a'} path={path}")
        return 0

    def lldb_get_module_by_index(self, this_ptr, index, base):
        trace(f"call into lldb_get_module_by_index index={index}")
        _, coreclr_base = self._scan_coreclr()
        if index == 0 and coreclr_base is not None:
            if base:
                base.contents.value = ctypes.c_uint64(coreclr_base).value
            trace(f"  -> base=0x{coreclr_base:x}")
            return 0
        return 0x80004005

    def lldb_get_module_by_module_name(self, this_ptr, name, startIndex, index, base):
        try:
            q = name.decode() if name else ""
        except Exception:
            q = ""
        trace(f"call into lldb_get_module_by_module_name name='{q}' startIndex={startIndex}")
        path, coreclr_base = self._scan_coreclr()
        if coreclr_base is None:
            return 0x80004005
        base_name = os.path.basename(path)
        if startIndex > 0:
            return 0x80004005
        # Match on canonical (platform-agnostic) names too so 'coreclr.dll' matches 'libcoreclr.so'
        if not q:
            match = True
        else:
            canon_q = self._canon_modname(q)
            canon_base = self._canon_modname(base_name)
            match = (
                q.lower() in base_name.lower() or
                canon_q == canon_base or
                canon_q in canon_base or
                canon_base in canon_q
            )
        if match:
            if index:
                index.contents.value = 0
            if base:
                base.contents.value = ctypes.c_uint64(coreclr_base).value
            trace(f"  -> index=0 base=0x{coreclr_base:x}")
            return 0
        return 0x80004005

    def lldb_get_module_by_offset(self, this_ptr, offset, startIndex, index, base):
        trace("call into lldb_get_module_by_offset")
        return 0x80004001

    def lldb_get_module_names(self, this_ptr, index, base, imageNameBuffer, imageNameBufferSize, imageNameSize, moduleNameBuffer, moduleNameBufferSize, moduleNameSize, loadedImageNameBuffer, loadedImageNameBufferSize, loadedImageNameSize):
        trace(f"call into lldb_get_module_names index={index} base={base}")
        path, coreclr_base = self._scan_coreclr()
        if not path:
            return 0x80004005
        if index != 0:
            if index != DEBUG_ANY_ID:
                return 0x80004005
            try:
                if base != ctypes.c_uint64(coreclr_base).value:
                    return 0x80004005
            except Exception:
                return 0x80004005
        img = path.encode('utf-8')
        name = os.path.basename(path).encode('utf-8')

        def fill(buf_voidp, bufSize, sizePtr, data_bytes):
            try:
                if sizePtr:
                    sizePtr.contents.value = len(data_bytes) + 1
                if not buf_voidp or not bufSize or bufSize <= 0:
                    return
                char_p = ctypes.cast(buf_voidp, ctypes.POINTER(ctypes.c_char))
                n = min(len(data_bytes), max(0, bufSize - 1))
                if n > 0:
                    ctypes.memmove(char_p, data_bytes, n)
                try:
                    char_p[n] = b"\x00"
                except Exception:
                    zero = (ctypes.c_char * 1)()
                    ctypes.memmove(ctypes.cast(ctypes.addressof(char_p.contents) + n, ctypes.c_void_p), zero, 1)
            except Exception as ex:
                trace(f"lldb_get_module_names.fill error: {ex}")

        fill(imageNameBuffer, imageNameBufferSize, imageNameSize, img)
        fill(moduleNameBuffer, moduleNameBufferSize, moduleNameSize, name)
        fill(loadedImageNameBuffer, loadedImageNameBufferSize, loadedImageNameSize, img)
        return 0

    def lldb_get_line_by_offset(self, this_ptr, offset, line, fileBuffer, fileBufferSize, fileSize, displacement):
        trace("call into lldb_get_line_by_offset")
        # Contract:
        # - offset: code address (absolute)
        # - line: out ULONG* (line number)
        # - fileBuffer: out char* (file path UTF-8)
        # - fileBufferSize: in ULONG (capacity)
        # - fileSize: out ULONG* (required length including NUL)
        # - displacement: out ULONG64* (delta between 'offset' and start of line mapping)
        # Return 0 (S_OK) on success, E_FAIL on not found or errors, but keep outputs consistent.
        # Implementation: use GDB 'info line *ADDR' and parse. Examples:
        #   Line 42 of "foo.cs" starts at address 0x7f... <...> and ends at 0x7f...
        #   No line information available for address 0x...
        try:
            addr = int(offset)
        except Exception:
            addr = 0
        # Initialize outputs to safe defaults
        try:
            if line:
                line.contents.value = 0
        except Exception:
            pass
        try:
            if fileSize:
                fileSize.contents.value = 0
        except Exception:
            pass
        try:
            if displacement:
                displacement.contents.value = 0
        except Exception:
            pass

        if not addr:
            return 0x80004005

        # First try managed-aware mapping via bridge helper (DAC + ISymbolService)
        try:
            bridge_fn = getattr(self, '_bridge_get_line', None)
        except Exception:
            bridge_fn = None
        if bridge_fn is not None:
            try:
                # Prepare temporary buffer for file path
                # If fileBuffer is provided, we can pass it directly, else use a temp buffer
                use_tmp = not fileBuffer or not fileBufferSize or fileBufferSize <= 0
                tmp_buf = None
                buf_ptr = None
                buf_size = int(fileBufferSize) if not use_tmp else 1024
                if use_tmp:
                    tmp_buf = ctypes.create_string_buffer(buf_size)
                    buf_ptr = ctypes.cast(tmp_buf, ctypes.c_char_p)
                else:
                    # fileBuffer may be an integer address from ctypes; normalize to char*
                    if isinstance(fileBuffer, int):
                        buf_ptr = ctypes.cast(fileBuffer, ctypes.c_char_p)
                    else:
                        buf_ptr = ctypes.cast(fileBuffer, ctypes.c_char_p)
                out_size = ctypes.c_uint(0)
                out_line = ctypes.c_uint(0)
                out_disp = ctypes.c_uint64(0)
                hr = bridge_fn(ctypes.c_uint64(addr), buf_ptr, ctypes.c_uint(buf_size), ctypes.byref(out_size), ctypes.byref(out_line), ctypes.byref(out_disp))
                if hr == 0 and out_line.value != 0:
                    # Success; fill outs and copy tmp buffer to user buffer if needed
                    if line:
                        line.contents.value = int(out_line.value)
                    if displacement:
                        displacement.contents.value = ctypes.c_uint64(out_disp.value).value
                    if fileSize:
                        fileSize.contents.value = int(out_size.value)
                    if use_tmp and fileBuffer and fileBufferSize and fileBufferSize > 0:
                        n = min(len(tmp_buf.value), max(0, int(fileBufferSize) - 1))
                        if n > 0:
                            ctypes.memmove(fileBuffer if isinstance(fileBuffer, int) else ctypes.cast(fileBuffer, ctypes.c_void_p).value, tmp_buf.raw, n)
                        # ensure NUL
                        dst = fileBuffer if isinstance(fileBuffer, int) else ctypes.cast(fileBuffer, ctypes.c_void_p).value
                        ctypes.memmove(dst + n, b"\x00", 1)
                    try:
                        trace_cat('disasm', f"[line] bridge 0x{addr:x} -> line {out_line.value}, size={out_size.value}, disp=0x{out_disp.value:x}")
                    except Exception:
                        pass
                    return 0
                else:
                    try:
                        trace_cat('disasm', f"[line] bridge miss hr=0x{hr & 0xFFFFFFFF:08x} for 0x{addr:x}")
                    except Exception:
                        pass
            except Exception as exb:
                try:
                    trace_cat('disasm', f"[line] bridge exception: {exb}")
                except Exception:
                    pass

        text = None
        try:
            text = gdb.execute(f"info line *0x{addr:x}", to_string=True) or ""
        except Exception as ex:
            try:
                trace_cat('disasm', f"[line] gdb info line error: {ex}")
            except Exception:
                pass
            text = ""

        # Parse for file, line, and start address
        src_file = None
        src_line = 0
        start_addr = None
        try:
            s = text.strip()
            if s and s.lower().startswith('line') and ' starts at address ' in s:
                # Try a robust parse without strict regex to handle variations
                # Expected pattern: Line <num> of "<file>" starts at address 0x<start> ...
                # Find 'Line ' and following number
                try:
                    after_line = s[5:].lstrip()  # after 'Line '
                    num_str = ''
                    i = 0
                    while i < len(after_line) and after_line[i].isdigit():
                        num_str += after_line[i]
                        i += 1
                    if num_str:
                        src_line = int(num_str)
                except Exception:
                    src_line = 0
                # Find quoted file name
                try:
                    q1 = s.find('"')
                    if q1 >= 0:
                        q2 = s.find('"', q1 + 1)
                        if q2 > q1:
                            src_file = s[q1+1:q2]
                except Exception:
                    src_file = None
                # Find 'starts at address 0x...'
                try:
                    key = 'starts at address '
                    k = s.find(key)
                    if k >= 0:
                        rest = s[k + len(key):].split()[0]
                        if rest.startswith('0x'):
                            start_addr = int(rest, 16)
                except Exception:
                    start_addr = None
        except Exception:
            pass

        if not src_file or not src_line or start_addr is None:
            try:
                trace_cat('disasm', f"[line] no mapping for 0x{addr:x}; raw='{(text or '').strip()[:120]}'")
            except Exception:
                pass
            return 0x80004005

        # Fill outputs
        try:
            if line:
                line.contents.value = int(src_line)
        except Exception:
            pass
        disp_val = 0
        try:
            if start_addr is not None and addr >= start_addr:
                disp_val = addr - start_addr
        except Exception:
            disp_val = 0
        try:
            if displacement:
                displacement.contents.value = ctypes.c_uint64(disp_val).value
        except Exception:
            pass

        # File buffer handling (UTF-8)
        file_bytes = b""
        try:
            file_bytes = (src_file or '').encode('utf-8', errors='replace')
        except Exception:
            file_bytes = b""
        try:
            if fileSize:
                fileSize.contents.value = len(file_bytes) + 1
        except Exception:
            pass
        try:
            if fileBuffer and fileBufferSize and fileBufferSize > 0:
                dst = fileBuffer if isinstance(fileBuffer, int) else ctypes.cast(fileBuffer, ctypes.c_void_p).value
                if dst:
                    n = min(len(file_bytes), max(0, int(fileBufferSize) - 1))
                    if n > 0:
                        ctypes.memmove(dst, file_bytes, n)
                    ctypes.memmove(dst + n, b"\x00", 1)
        except Exception as ex:
            try:
                trace_cat('disasm', f"[line] fileBuffer write error: {ex}")
            except Exception:
                pass

        try:
            trace_cat('disasm', f"[line] 0x{addr:x} -> {src_file}:{src_line} +0x{disp_val:x}")
        except Exception:
            pass
        return 0

    def lldb_get_source_file_line_offsets(self, this_ptr, file, buffer, bufferLines, fileLines):
        trace("call into lldb_get_source_file_line_offsets")
        return 0x80004001

    def lldb_find_source_file(self, this_ptr, startElement, file, flags, foundElement, buffer, bufferSize, foundSize):
        trace("call into lldb_find_source_file")
        return 0x80004001

    def lldb_get_current_process_system_id(self, this_ptr, id_ptr):
        trace("call into lldb_get_current_process_system_id")
        if id_ptr:
            pid = self._get_pid() or 0
            id_ptr.contents.value = pid
        return 0

    def lldb_get_current_thread_id(self, this_ptr, id_ptr):
        trace("call into lldb_get_current_thread_id")
        if id_ptr:
            threads = self._get_threads()
            cur = gdb.selected_thread()
            engine_id = 0
            if cur is not None:
                try:
                    for idx, t in enumerate(threads):
                        if t.ptid == cur.ptid:
                            engine_id = idx
                            break
                except Exception:
                    pass
            id_ptr.contents.value = engine_id
        return 0

    def lldb_set_current_thread_id(self, this_ptr, id_value):
        trace("call into lldb_set_current_thread_id")
        try:
            threads = self._get_threads()
            if 0 <= id_value < len(threads):
                threads[id_value].switch()
                self._current_thread_sysid = self._thread_sysid(threads[id_value])
        except Exception:
            pass
        return 0

    def lldb_get_current_thread_system_id(self, this_ptr, sysId):
        trace("call into lldb_get_current_thread_system_id")
        if sysId:
            sys_id = self._current_thread_sysid
            if not sys_id:
                try:
                    cur = gdb.selected_thread()
                    if cur is not None:
                        sys_id = self._thread_sysid(cur)
                except Exception:
                    sys_id = 0
            sysId.contents.value = sys_id or 0
        return 0

    def lldb_get_thread_id_by_system_id(self, this_ptr, sysId, id_ptr):
        trace("call into lldb_get_thread_id_by_system_id")
        try:
            if id_ptr:
                threads = self._get_threads()
                for idx, t in enumerate(threads):
                    if self._thread_sysid(t) == sysId:
                        id_ptr.contents.value = idx
                        return 0
        except Exception:
            pass
        return 0x80004005

    def lldb_get_thread_context_by_system_id(self, this_ptr, sysId, contextFlags, contextSize, context):
        trace("call into lldb_get_thread_context_by_system_id")
        if not context or contextSize < 128:
            return 0x80004005
        try:
            thread = self._find_thread_by_sysid(sysId)
            if thread is None:
                return 0x80004005
            frame = None
            try:
                thread.switch()
                frame = gdb.newest_frame()
            except Exception:
                pass
            if frame is None:
                return 0x80004005
            # Arch-specific handling
            mtype = self._detect_machine_type()
            ctypes.memset(context, 0, contextSize)
            if mtype == IMAGE_FILE_MACHINE_AMD64:
                # Fill minimal AMD64 DT_CONTEXT
                CONTEXT_AMD64 = 0x00100000
                CONTEXT_CONTROL = 0x00000001
                CONTEXT_INTEGER = 0x00000002
                flags = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER
                ctypes.cast(context, ctypes.POINTER(ULONG)).contents.value = flags
                self._fill_amd64_dt_context(frame, flags, ctypes.cast(context, ctypes.c_void_p))
            else:
                # For ARM64, we don't currently marshal a Windows-style CONTEXT.
                # Leave buffer zeroed and return E_NOTIMPL so callers can fall back.
                try:
                    # Still update our cached offsets below
                    pass
                except Exception:
                    pass
            # Update cache for this sysid so offset getters can avoid using gdb APIs
            try:
                # Cross-arch register names
                def _reg(name_list):
                    for nm in name_list:
                        try:
                            return int(frame.read_register(nm))
                        except Exception:
                            continue
                    return 0
                rip = _reg(['rip', 'pc'])
                rsp = _reg(['rsp', 'sp'])
                rbp = _reg(['rbp', 'fp', 'x29'])
                self._context_cache[sysId] = {'rip': rip, 'rsp': rsp, 'rbp': rbp}
                # Remember current thread sysid
                self._current_thread_sysid = sysId
            except Exception:
                pass
            if mtype == IMAGE_FILE_MACHINE_AMD64:
                return 0
            else:
                return 0x80004001
        except Exception as ex:
            trace(f"lldb_get_thread_context_by_system_id error: {ex}")
            return 0x80004005

    def lldb_get_value_by_name(self, this_ptr, name, value_ptr):
        trace("call into lldb_get_value_by_name")
        return 0x80004001

    def lldb_get_instruction_offset(self, this_ptr, offset_ptr):
        trace("call into lldb_get_instruction_offset")
        try:
            if offset_ptr:
                rip = 0
                if self._current_thread_sysid in self._context_cache:
                    rip = self._context_cache[self._current_thread_sysid].get('rip', 0)
                if not rip:
                    try:
                        fr = gdb.newest_frame()
                        if fr is not None:
                            try:
                                rip = int(fr.read_register('rip'))
                            except Exception:
                                rip = int(fr.read_register('pc'))
                    except Exception:
                        rip = 0
                if rip:
                    offset_ptr.contents.value = ctypes.c_uint64(rip).value
                    return 0
        except Exception:
            pass
        return 0x80004005

    def lldb_get_stack_offset(self, this_ptr, offset_ptr):
        trace("call into lldb_get_stack_offset")
        try:
            if offset_ptr:
                rsp = 0
                if self._current_thread_sysid in self._context_cache:
                    rsp = self._context_cache[self._current_thread_sysid].get('rsp', 0)
                if not rsp:
                    try:
                        fr = gdb.newest_frame()
                        if fr is not None:
                            try:
                                rsp = int(fr.read_register('rsp'))
                            except Exception:
                                rsp = int(fr.read_register('sp'))
                    except Exception:
                        rsp = 0
                if rsp:
                    offset_ptr.contents.value = ctypes.c_uint64(rsp).value
                    return 0
        except Exception:
            pass
        return 0x80004005

    def lldb_get_frame_offset(self, this_ptr, offset_ptr):
        trace("call into lldb_get_frame_offset")
        try:
            if offset_ptr:
                rbp = 0
                if self._current_thread_sysid in self._context_cache:
                    rbp = self._context_cache[self._current_thread_sysid].get('rbp', 0)
                if not rbp:
                    try:
                        fr = gdb.newest_frame()
                        if fr is not None:
                            # Try common frame-pointer names across arch
                            for nm in ('rbp', 'fp', 'x29'):
                                try:
                                    rbp = int(fr.read_register(nm))
                                    if rbp:
                                        break
                                except Exception:
                                    continue
                    except Exception:
                        rbp = 0
                if rbp:
                    offset_ptr.contents.value = ctypes.c_uint64(rbp).value
                    return 0
        except Exception:
            pass
        return 0x80004005

    # --- IDebuggerServices ---
    def dbg_get_operating_system(self, this_ptr, os_ptr):
        if os_ptr:
            os_ptr.contents.value = 2
        return 0

    def dbg_add_command(self, this_ptr, command, help_text, aliases, numberOfAliases):
        return 0

    def dbg_output_string(self, this_ptr, mask, message):
        try:
            if getattr(self, "_interrupted", False):
                return
            msg = message.decode() if isinstance(message, (bytes, bytearray)) else str(message)
            # Suppress noisy early messages before runtime entry is hit
            if not getattr(self, "_runtime_initialized", False):
                suppressed = (
                    "Failed to find runtime module (libcoreclr.so)" in msg or
                    "Extension commands need it in order to have something to do." in msg or
                    "https://go.microsoft.com/fwlink/?linkid=2135652" in msg
                )
                if suppressed:
                    return
            # Optionally capture output for callers (e.g., soshelp addendum heuristic)
            try:
                if getattr(self, "_capture_output", False):
                    lst = getattr(self, "_capture_output_list", None)
                    if lst is None:
                        lst = []
                        self._capture_output_list = lst
                    lst.append(msg)
            except Exception:
                pass
            gdb.write(msg)
        except KeyboardInterrupt:
            # User quit the pager; set interrupted and stop writing further
            self._interrupted = True
        except Exception:
            pass

    def dbg_get_module_info(self, this_ptr, index, moduleBase, moduleSize, timestamp, checksum):
        path, base_addr = self._scan_coreclr()
        if index != 0 or base_addr is None:
            return 0x80004005
        # Determine module size by scanning all libcoreclr.so mappings
        pid = self._get_pid()
        min_start = None
        max_end = None
        try:
            if pid and path:
                maps_path = f"/proc/{pid}/maps"
                with open(maps_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if 'libcoreclr.so' not in line:
                            continue
                        parts = line.strip().split()
                        if len(parts) < 6:
                            continue
                        p = ' '.join(parts[5:])
                        if p.endswith(' (deleted)'):
                            p = p[:-10]
                        if not p.startswith('/') or p != path:
                            continue
                        try:
                            start_str, end_str = parts[0].split('-')
                            start = int(start_str, 16)
                            end = int(end_str, 16)
                        except Exception:
                            continue
                        if min_start is None or start < min_start:
                            min_start = start
                        if max_end is None or end > max_end:
                            max_end = end
        except Exception as ex:
            trace(f"dbg_get_module_info maps scan error: {ex}")
        size_val = 0
        if min_start is not None and max_end is not None and max_end > min_start:
            size_val = max_end - min_start
        if moduleBase:
            moduleBase.contents.value = ctypes.c_uint64(base_addr).value
        if moduleSize:
            moduleSize.contents.value = ctypes.c_uint64(size_val).value
        if timestamp:
            timestamp.contents.value = 0
        if checksum:
            checksum.contents.value = 0
        return 0

    def dbg_get_module_names(self, this_ptr, index, base, imageNameBuffer, imageNameBufferSize, imageNameSize, moduleNameBuffer, moduleNameBufferSize, moduleNameSize, loadedImageNameBuffer, loadedImageNameBufferSize, loadedImageNameSize):
        path, _ = self._scan_coreclr()
        if index != 0 or not path:
            return 0x80004005
        img = path.encode('utf-8')
        name = os.path.basename(path).encode('utf-8')
        def fill(buf_voidp, bufSize, sizePtr, data_bytes):
            try:
                if sizePtr:
                    sizePtr.contents.value = len(data_bytes) + 1
                if not buf_voidp or not bufSize or bufSize <= 0:
                    return
                addr = buf_voidp if isinstance(buf_voidp, int) else ctypes.cast(buf_voidp, ctypes.c_void_p).value
                if not addr:
                    return
                n = min(len(data_bytes), max(0, bufSize - 1))
                if n > 0:
                    ctypes.memmove(addr, data_bytes, n)
                ctypes.memmove(addr + n, b"\x00", 1)
            except Exception as ex:
                trace(f"dbg_get_module_names.fill error: {ex}")
        fill(imageNameBuffer, imageNameBufferSize, imageNameSize, img)
        fill(moduleNameBuffer, moduleNameBufferSize, moduleNameSize, name)
        fill(loadedImageNameBuffer, loadedImageNameBufferSize, loadedImageNameSize, img)
        return 0

    def dbg_get_number_threads(self, this_ptr, number_ptr):
        if number_ptr:
            try:
                number_ptr.contents.value = len(self._get_threads())
            except Exception:
                number_ptr.contents.value = 0
        return 0

    def dbg_get_thread_ids_by_index(self, this_ptr, start, count, ids, sysIds):
        try:
            threads = self._get_threads()
            n = len(threads)
            if start >= n or count == 0:
                return 0
            limit = min(count, n - start)
            for i in range(limit):
                idx = start + i
                t = threads[idx]
                engine_id = idx
                sys_id = self._thread_sysid(t)
                if ids:
                    try:
                        ids[i] = engine_id
                    except Exception:
                        pass
                if sysIds:
                    try:
                        sysIds[i] = sys_id
                    except Exception:
                        pass
            return 0
        except Exception as ex:
            trace(f"dbg_get_thread_ids_by_index error: {ex}")
            return 0x80004005

    def dbg_set_current_thread_system_id(self, this_ptr, sysId):
        try:
            t = self._find_thread_by_sysid(sysId)
            if t is not None:
                t.switch()
                self._current_thread_sysid = sysId
                return 0
        except Exception:
            pass
        return 0x80004005

    def dbg_get_thread_teb(self, this_ptr, sysId, pteb):
        return 0x80004001

    def dbg_get_symbol_path(self, this_ptr, buffer, bufferSize, pathSize):
        # Report empty symbol path and write a terminating NUL if a buffer is provided
        if pathSize:
            pathSize.contents.value = 1
        try:
            if buffer and bufferSize and bufferSize > 0:
                # 'buffer' may be an integer address or a c_void_p; normalize to address
                addr = buffer if isinstance(buffer, int) else ctypes.cast(buffer, ctypes.c_void_p).value
                if addr:
                    ctypes.memmove(addr, b"\x00", 1)
        except Exception:
            pass
        return 0

    def dbg_get_symbol_by_offset(self, this_ptr, moduleIndex, offset, nameBuffer, nameBufferSize, nameSize, displacement):
        return 0x80004001

    def dbg_get_offset_by_symbol(self, this_ptr, moduleIndex, name, offset):
        return 0x80004001

    def dbg_get_type_id(self, this_ptr, moduleIndex, typeName, typeId):
        return 0x80004001

    def dbg_get_field_offset(self, this_ptr, moduleIndex, typeName, typeId, fieldName, offset):
        return 0x80004001

    def dbg_get_output_width(self, this_ptr):
        return 80

    def dbg_supports_dml(self, this_ptr, supported):
        if supported:
            supported.contents.value = 0
        return 0

    def dbg_output_dml_string(self, this_ptr, mask, message):
        self.dbg_output_string(this_ptr, mask, message)

    def dbg_flush_check(self, this_ptr):
        # Optionally could be used to poll/clear; leave as no-op
        return None

    # Helper to reset interrupt state at the start of each SOS command
    def clear_interrupt(self):
        self._interrupted = False

    def dbg_execute_host_command(self, this_ptr, commandLine, callback):
        return 0x80004001

    def dbg_get_dac_signature_ver_settings(self, this_ptr, enabled_ptr):
        if enabled_ptr:
            enabled_ptr.contents.value = 0
        return 0
