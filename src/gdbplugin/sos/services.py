import os
import sys
import ctypes
import gdb

# Allow importing when sourced directly (sos.py adjusts sys.path similarly)
from abi import *
from tracing import TRACE_ENABLED, trace


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
        self._registered_debugger = None

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
                path, base = self._scan_coreclr()
                if not path or base is None:
                    return
                ETYPE = ctypes.CFUNCTYPE(HRESULT, ctypes.c_void_p)
                ecb = ctypes.cast(self._exception_cb, ETYPE)
                hr = ecb(ctypes.c_void_p(ctypes.addressof(self.illldb_ptr)))
                trace(f"[stop-hook] Exception callback HR=0x{int(hr) & 0xFFFFFFFF:08x}")
            except Exception as ex:
                trace(f"[stop-hook] error: {ex}")
            finally:
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
                trace(f"[new-objfile] detected {fname}")
                # Fire runtime-loaded and exception callbacks once
                self._invoke_runtime_loaded_cb_once()
                self._invoke_exception_cb_once()
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
            trace(f"[invoke] Exception callback HR=0x{int(hr) & 0xFFFFFFFF:08x}")
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
            CBTYPE = ctypes.CFUNCTYPE(HRESULT, ctypes.c_void_p)
            cb = ctypes.cast(self._runtime_loaded_cb, CBTYPE)
            hr = cb(ctypes.c_void_p(ctypes.addressof(self.illldb_ptr)))
            self._runtime_loaded_fired = True
            trace(f"[invoke] RuntimeLoaded callback HR=0x{int(hr) & 0xFFFFFFFF:08x}")
        except Exception as ex:
            trace(f"[invoke] runtime-loaded-cb error: {ex}")

    # --- IMemoryService ---
    def read_virtual(self, this_ptr, address, buffer, bytes_requested, bytes_read_ptr):
        trace("call into read_virtual")
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
            return 0 if total_read > 0 else 0x80070005
        except Exception:
            if bytes_read_ptr:
                bytes_read_ptr.contents.value = total_read
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
        if out_ptr:
            out_ptr.contents.value = 0
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
        trace("call into lldb2_set_runtime_loaded_callback")
        try:
            # Save the callback pointer
            self._runtime_loaded_cb = callback

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
                        # Cast callback and call with ILLDBServices* (as void*)
                        if services_self._runtime_loaded_cb:
                            CBTYPE = ctypes.CFUNCTYPE(HRESULT, ctypes.c_void_p)
                            cb = ctypes.cast(services_self._runtime_loaded_cb, CBTYPE)
                            hr = cb(ctypes.c_void_p(ctypes.addressof(services_self.illldb_ptr)))
                            trace(f"RuntimeLoaded callback HR=0x{int(hr) & 0xFFFFFFFF:08x}")
                        # Immediately trigger the exception callback once to process CLR notifications
                        if getattr(services_self, "_exception_cb", None):
                            ETYPE = ctypes.CFUNCTYPE(HRESULT, ctypes.c_void_p)
                            ecb = ctypes.cast(services_self._exception_cb, ETYPE)
                            ehr = ecb(ctypes.c_void_p(ctypes.addressof(services_self.illldb_ptr)))
                            trace(f"Exception callback HR=0x{int(ehr) & 0xFFFFFFFF:08x}")
                    except Exception as ex:
                        trace(f"RuntimeLoaded callback error: {ex}")
                    finally:
                        # One-shot: delete breakpoint and continue
                        try:
                            self_inner.delete()
                        except Exception:
                            pass
                    # Return False to auto-continue
                    return False

            # If CoreCLR is already loaded, fire immediately and skip installing the bp
            self._invoke_runtime_loaded_cb_once()
            if not self._runtime_loaded_fired:
                # Also listen for lib loads in case symbol binding is delayed
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
                        self._runtime_loaded_bp = _RuntimeLoadedBP('coreclr_execute_assembly')
                except Exception:
                    # Fallback to command if constructor fails
                    try:
                        gdb.execute('break coreclr_execute_assembly', to_string=True)
                    except Exception as ex2:
                        trace(f"[runtime-bp] failed to set fallback bp: {ex2}")
            return 0
        except Exception as ex:
            trace(f"lldb2_set_runtime_loaded_callback error: {ex}")
            return 0x80004005

    # --- ILLDBServices ---
    def lldb_get_coreclr_directory(self, this_ptr):
        trace("call into lldb_get_coreclr_directory")
        try:
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
        trace("call into lldb_set_exception_callback")
        try:
            self._exception_cb = cb
            # Ensure our stop hook is connected so SOS receives notifications on every stop
            if not self._stop_hook_registered:
                try:
                    gdb.events.stop.connect(self._stop_handler)
                    self._stop_hook_registered = True
                    trace("[stop-hook] connected")
                except Exception as ex:
                    trace(f"[stop-hook] connect error: {ex}")
            # Try to notify immediately if CoreCLR is already present
            self._invoke_exception_cb_once()
            # Also connect new-objfile hook to catch when CoreCLR loads later
            if not self._newobj_hook_registered:
                try:
                    gdb.events.new_objfile.connect(self._newobj_handler)
                    self._newobj_hook_registered = True
                    trace("[new-objfile] connected")
                except Exception as ex:
                    trace(f"[new-objfile] connect error: {ex}")
            # As a fallback, install a one-shot pending breakpoint on coreclr entry
            # so we get a stop to deliver CLR notifications even if no other bps are set.
            services_self = self
            class _CoreClrEntryBP(gdb.Breakpoint):
                def stop(self_inner):
                    try:
                        services_self._invoke_exception_cb_once()
                    except Exception as _ex:
                        trace(f"[entry-bp] error: {_ex}")
                    finally:
                        try:
                            self_inner.delete()
                        except Exception:
                            pass
                    return False
            try:
                # Avoid duplicating the user's existing runtime entry breakpoint
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
                    trace('[entry-bp] skip: coreclr_execute_assembly breakpoint already exists')
                else:
                    _CoreClrEntryBP('coreclr_execute_assembly')
                    trace('[entry-bp] breakpoint set on coreclr_execute_assembly')
            except Exception:
                try:
                    gdb.execute('break coreclr_execute_assembly', to_string=True)
                    trace('[entry-bp] break command issued for coreclr_execute_assembly')
                except Exception as ex:
                    trace(f"[entry-bp] failed to set breakpoint: {ex}")
            return 0
        except Exception:
            return 0x80004005

    def lldb_clear_exception_callback(self, this_ptr):
        trace("call into lldb_clear_exception_callback")
        self._exception_cb = None
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
        # Report a live session when we have a real OS PID; otherwise treat as dump.
        # SOS uses Qualifier >= DEBUG_DUMP_SMALL to detect dumps (see IsDumpFile()).
        if debugClass:
            debugClass.contents.value = DEBUG_CLASS_USER_WINDOWS
        if qualifier:
            pid = self._get_pid()
            if pid and pid > 0:
                qualifier.contents.value = 0  # live user-mode
            else:
                qualifier.contents.value = DEBUG_DUMP_FULL
        return 0

    def lldb_get_page_size(self, this_ptr, size_ptr):
        trace("call into lldb_get_page_size")
        if size_ptr:
            size_ptr.contents.value = 4096
        return 0

    def lldb_get_processor_type(self, this_ptr, type_ptr):
        trace("call into lldb_get_processor_type")
        if type_ptr:
            type_ptr.contents.value = IMAGE_FILE_MACHINE_AMD64
        return 0

    def lldb_execute(self, this_ptr, outctl, command, flags):
        trace("call into lldb_execute")
        try:
            cmd = command.decode() if command else ""
            if cmd and TRACE_ENABLED:
                gdb.write(f"[ILLDBServices.Execute] {cmd}\n")
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
        # Goal: never hang the caller. Either return one instruction text and advance endOffset,
        # or return S_FALSE with endOffset advanced so the caller makes progress.
        try:
            text = None
            # Try using gdb to disassemble a single instruction at the given address.
            try:
                # Use x/1i to get one instruction; suppress pagination noise.
                out = gdb.execute(f"x/1i 0x{int(offset):x}", to_string=True)
                # Typical format: "0xADDRESS:\tOPCODE ...\n" – strip the leading address
                if out:
                    line = out.strip().splitlines()[0]
                    # Split at first tab or colon space
                    parts = line.split("\t", 1)
                    if len(parts) == 2:
                        text = parts[1]
                    else:
                        # Fallback: after colon
                        cidx = line.find(":")
                        text = line[cidx+1:].strip() if cidx >= 0 else line
            except Exception:
                text = None

            written = 0
            if text and buffer and bufferSize and bufferSize > 1:
                try:
                    bs = text.encode('utf-8', errors='replace')
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
                disSize.contents.value = written

            # Always advance by at least 1 byte to ensure forward progress if we can't decode size.
            adv = 1
            try:
                # Try to infer instruction size by looking up next address from gdb output
                # Not always available; keep minimal advancement.
                pass
            except Exception:
                pass
            if endOffset:
                endOffset.contents.value = ctypes.c_uint64(int(offset) + adv).value
            # Return S_OK if we wrote text, otherwise S_FALSE
            return 0 if written > 0 else 1
        except Exception:
            # On any error, indicate no text but still advance to avoid infinite loops.
            try:
                if disSize:
                    disSize.contents.value = 0
                if endOffset:
                    endOffset.contents.value = ctypes.c_uint64(int(offset) + 1).value
            except Exception:
                pass
            return 1

    def lldb_get_context_stack_trace(self, this_ptr, startContext, startContextSize, frames, framesSize, frameContexts, frameContextsSize, frameContextsEntrySize, framesFilled):
        trace("call into lldb_get_context_stack_trace")
        return 0x80004001

    def lldb_read_virtual(self, this_ptr, address, buffer, bufferSize, bytesRead):
        trace("call into lldb_read_virtual")
        return self.read_virtual(this_ptr, address, buffer, bufferSize, bytesRead)

    def lldb_write_virtual(self, this_ptr, address, buffer, bufferSize, bytesWritten):
        trace("call into lldb_write_virtual")
        return 0x80004001

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
        if not q or q.lower() in base_name.lower():
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
        return 0x80004001

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
        threads = self._get_threads()
        try:
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
            # Fill minimal AMD64 DT_CONTEXT
            # Write ContextFlags at offset matching DT_CONTEXT layout: first 4 bytes
            ctypes.memset(context, 0, contextSize)
            # For SOS, any non-zero flags that include CONTROL|INTEGER are acceptable
            CONTEXT_AMD64 = 0x00100000
            CONTEXT_CONTROL = 0x00000001
            CONTEXT_INTEGER = 0x00000002
            flags = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER
            ctypes.cast(context, ctypes.POINTER(ULONG)).contents.value = flags
            self._fill_amd64_dt_context(frame, flags, ctypes.cast(context, ctypes.c_void_p))
            # Update cache for this sysid so offset getters can avoid using gdb APIs
            try:
                rip = int(frame.read_register('rip'))
                rsp = int(frame.read_register('rsp'))
                rbp = int(frame.read_register('rbp'))
                self._context_cache[sysId] = {'rip': rip, 'rsp': rsp, 'rbp': rbp}
                # Remember current thread sysid
                self._current_thread_sysid = sysId
            except Exception:
                pass
            return 0
        except Exception as ex:
            trace(f"lldb_get_thread_context_by_system_id error: {ex}")
            return 0x80004005

    def lldb_get_value_by_name(self, this_ptr, name, value_ptr):
        trace("call into lldb_get_value_by_name")
        return 0x80004001

    def lldb_get_instruction_offset(self, this_ptr, offset_ptr):
        trace("call into lldb_get_instruction_offset")
        try:
            if offset_ptr and self._current_thread_sysid in self._context_cache:
                rip = self._context_cache[self._current_thread_sysid].get('rip', 0)
                offset_ptr.contents.value = ctypes.c_uint64(rip).value
                return 0
        except Exception:
            pass
        return 0x80004005

    def lldb_get_stack_offset(self, this_ptr, offset_ptr):
        trace("call into lldb_get_stack_offset")
        try:
            if offset_ptr and self._current_thread_sysid in self._context_cache:
                rsp = self._context_cache[self._current_thread_sysid].get('rsp', 0)
                offset_ptr.contents.value = ctypes.c_uint64(rsp).value
                return 0
        except Exception:
            pass
        return 0x80004005

    def lldb_get_frame_offset(self, this_ptr, offset_ptr):
        trace("call into lldb_get_frame_offset")
        try:
            if offset_ptr and self._current_thread_sysid in self._context_cache:
                rbp = self._context_cache[self._current_thread_sysid].get('rbp', 0)
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
            gdb.write(message.decode() if isinstance(message, (bytes, bytearray)) else str(message))
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
