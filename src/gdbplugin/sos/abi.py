import ctypes

# Basic types
HRESULT = ctypes.c_int32
ULONG = ctypes.c_uint32
ULONG64 = ctypes.c_uint64
PVOID = ctypes.c_void_p
CHAR = ctypes.c_char
PCSTR = ctypes.c_char_p

# GUID
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", (ctypes.c_ubyte * 8)),
    ]

# IIDs
IID_IUnknown = GUID(0x00000000, 0x0000, 0x0000, (0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))
IID_IMemoryService = GUID(0x84a8922E, 0x3C6C, 0x4499, (0x9B, 0x4A, 0x3A, 0x62, 0x24, 0x43, 0x5A, 0x79))
IID_IDebuggerServices = GUID(0xB4640016, 0x6CA0, 0x468E, (0xBA, 0x2C, 0x1F, 0xFF, 0x28, 0xDE, 0x7B, 0x72))
IID_IHost = GUID(0xE0CD8534, 0xA88B, 0x40D7, (0x91, 0xBA, 0x1B, 0x4C, 0x92, 0x57, 0x61, 0xE9))
IID_ILLDBServices2 = GUID(0x012F32F0, 0x33BA, 0x4E8E, (0xBC, 0x01, 0x03, 0x7D, 0x38, 0x2D, 0x8A, 0x5E))
IID_ILLDBServices = GUID(0x2E6C569A, 0x9E14, 0x4DA4, (0x9D, 0xFC, 0xCD, 0xB7, 0x3A, 0x53, 0x25, 0x66))
IID_IHostServices = GUID(0x27B2CB8D, 0xBDEE, 0x4CBD, (0xB6, 0xEF, 0x75, 0x88, 0x0D, 0x76, 0xD4, 0x6F))

# Constants
DEBUG_CLASS_USER_WINDOWS = 2
DEBUG_DUMP_FULL = 1026
IMAGE_FILE_MACHINE_AMD64 = 0x8664
DEBUG_ANY_ID = 0xFFFFFFFF

# Vtable function signatures
QI_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(GUID), ctypes.POINTER(PVOID))
ADDREF_FUNC_TYPE = ctypes.CFUNCTYPE(ULONG, PVOID)
RELEASE_FUNC_TYPE = ctypes.CFUNCTYPE(ULONG, PVOID)
READ_VIRTUAL_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))
GET_OPERATING_SYSTEM_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ctypes.c_int))
DBG_GET_DEBUGGEE_TYPE_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))
DBG_GET_PROCESSOR_TYPE_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))
DBG_ADD_COMMAND_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, PCSTR, ctypes.POINTER(PCSTR), ctypes.c_int)
DBG_OUTPUT_STRING_FUNC_TYPE = ctypes.CFUNCTYPE(None, PVOID, ULONG, PCSTR)
DBG_READ_VIRTUAL_FUNC_TYPE = READ_VIRTUAL_FUNC_TYPE
DBG_WRITE_VIRTUAL_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))
DBG_GET_NUMBER_MODULES_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))
DBG_GET_MODULE_BY_INDEX_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64))
DBG_GET_MODULE_NAMES_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG))
DBG_GET_MODULE_INFO_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64), ctypes.POINTER(ULONG64), ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))
DBG_GET_MODULE_VERSION_INFO_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, PCSTR, PVOID, ULONG, ctypes.POINTER(ULONG))
DBG_GET_MODULE_BY_MODNAME_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))
DBG_GET_NUMBER_THREADS_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))
DBG_GET_THREAD_IDS_BY_INDEX_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))
DBG_GET_THREAD_CONTEXT_BY_SYSID_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, PVOID)
DBG_GET_CURRENT_PROCESS_SYSID_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))
DBG_GET_CURRENT_THREAD_SYSID_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))
DBG_SET_CURRENT_THREAD_SYSID_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG)
DBG_GET_THREAD_TEB_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64))
DBG_VIRTUAL_UNWIND_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.c_uint32, PVOID)
DBG_GET_SYMBOL_PATH_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG))
DBG_GET_SYMBOL_BY_OFFSET_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))
DBG_GET_OFFSET_BY_SYMBOL_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ctypes.POINTER(ULONG64))
DBG_GET_TYPE_ID_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ctypes.POINTER(ULONG64))
DBG_GET_FIELD_OFFSET_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ULONG64, PCSTR, ctypes.POINTER(ULONG))
DBG_GET_OUTPUT_WIDTH_FUNC_TYPE = ctypes.CFUNCTYPE(ULONG, PVOID)
DBG_SUPPORTS_DML_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))
DBG_OUTPUT_DML_STRING_FUNC_TYPE = ctypes.CFUNCTYPE(None, PVOID, ULONG, PCSTR)
DBG_ADD_MODULE_SYMBOL_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID, PCSTR)
DBG_GET_LAST_EVENT_INFO_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG), ctypes.POINTER(ULONG), PVOID, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG))
DBG_FLUSH_CHECK_FUNC_TYPE = ctypes.CFUNCTYPE(None, PVOID)
DBG_EXECUTE_HOST_COMMAND_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, PVOID)
DBG_GET_DAC_SIG_VER_SETTINGS_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ctypes.c_int))
GET_HOST_TYPE_FUNC_TYPE = ctypes.CFUNCTYPE(ctypes.c_int, PVOID)
GET_SERVICE_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(GUID), ctypes.POINTER(PVOID))
GET_CURRENT_TARGET_FUNC_TYPE = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(PVOID))

HOSTSERVICES_GETHOST = ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(PVOID))
HOSTSERVICES_REGISTERDEBUGGER = ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID)
HOSTSERVICES_CREATETARGET = ctypes.CFUNCTYPE(HRESULT, PVOID)
HOSTSERVICES_UPDATETARGET = ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG)
HOSTSERVICES_FLUSHTARGET = ctypes.CFUNCTYPE(None, PVOID)
HOSTSERVICES_DESTROYTARGET = ctypes.CFUNCTYPE(None, PVOID)
HOSTSERVICES_DISPATCHCOMMAND = ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, PCSTR, ctypes.c_bool)
HOSTSERVICES_UNINITIALIZE = ctypes.CFUNCTYPE(None, PVOID)

# Vtable structures
class IUnknownVtbl(ctypes.Structure):
    _fields_ = [("QueryInterface", QI_FUNC_TYPE), ("AddRef", ADDREF_FUNC_TYPE), ("Release", RELEASE_FUNC_TYPE)]

class IMemoryServiceVtbl(ctypes.Structure):
    _fields_ = [("IUnknown", IUnknownVtbl), ("ReadVirtual", READ_VIRTUAL_FUNC_TYPE)]

class IDebuggerServicesVtbl(ctypes.Structure):
    _fields_ = [
        ("IUnknown", IUnknownVtbl),
        ("GetOperatingSystem", GET_OPERATING_SYSTEM_FUNC_TYPE),
        ("GetDebuggeeType", DBG_GET_DEBUGGEE_TYPE_FUNC_TYPE),
        ("GetProcessorType", DBG_GET_PROCESSOR_TYPE_FUNC_TYPE),
        ("AddCommand", DBG_ADD_COMMAND_FUNC_TYPE),
        ("OutputString", DBG_OUTPUT_STRING_FUNC_TYPE),
        ("ReadVirtual", DBG_READ_VIRTUAL_FUNC_TYPE),
        ("WriteVirtual", DBG_WRITE_VIRTUAL_FUNC_TYPE),
        ("GetNumberModules", DBG_GET_NUMBER_MODULES_FUNC_TYPE),
        ("GetModuleByIndex", DBG_GET_MODULE_BY_INDEX_FUNC_TYPE),
        ("GetModuleNames", DBG_GET_MODULE_NAMES_FUNC_TYPE),
        ("GetModuleInfo", DBG_GET_MODULE_INFO_FUNC_TYPE),
        ("GetModuleVersionInformation", DBG_GET_MODULE_VERSION_INFO_FUNC_TYPE),
        ("GetModuleByModuleName", DBG_GET_MODULE_BY_MODNAME_FUNC_TYPE),
        ("GetNumberThreads", DBG_GET_NUMBER_THREADS_FUNC_TYPE),
        ("GetThreadIdsByIndex", DBG_GET_THREAD_IDS_BY_INDEX_FUNC_TYPE),
        ("GetThreadContextBySystemId", DBG_GET_THREAD_CONTEXT_BY_SYSID_FUNC_TYPE),
        ("GetCurrentProcessSystemId", DBG_GET_CURRENT_PROCESS_SYSID_FUNC_TYPE),
        ("GetCurrentThreadSystemId", DBG_GET_CURRENT_THREAD_SYSID_FUNC_TYPE),
        ("SetCurrentThreadSystemId", DBG_SET_CURRENT_THREAD_SYSID_FUNC_TYPE),
        ("GetThreadTeb", DBG_GET_THREAD_TEB_FUNC_TYPE),
        ("VirtualUnwind", DBG_VIRTUAL_UNWIND_FUNC_TYPE),
        ("GetSymbolPath", DBG_GET_SYMBOL_PATH_FUNC_TYPE),
        ("GetSymbolByOffset", DBG_GET_SYMBOL_BY_OFFSET_FUNC_TYPE),
        ("GetOffsetBySymbol", DBG_GET_OFFSET_BY_SYMBOL_FUNC_TYPE),
        ("GetTypeId", DBG_GET_TYPE_ID_FUNC_TYPE),
        ("GetFieldOffset", DBG_GET_FIELD_OFFSET_FUNC_TYPE),
        ("GetOutputWidth", DBG_GET_OUTPUT_WIDTH_FUNC_TYPE),
        ("SupportsDml", DBG_SUPPORTS_DML_FUNC_TYPE),
        ("OutputDmlString", DBG_OUTPUT_DML_STRING_FUNC_TYPE),
        ("AddModuleSymbol", DBG_ADD_MODULE_SYMBOL_FUNC_TYPE),
        ("GetLastEventInformation", DBG_GET_LAST_EVENT_INFO_FUNC_TYPE),
        ("FlushCheck", DBG_FLUSH_CHECK_FUNC_TYPE),
        ("ExecuteHostCommand", DBG_EXECUTE_HOST_COMMAND_FUNC_TYPE),
        ("GetDacSignatureVerificationSettings", DBG_GET_DAC_SIG_VER_SETTINGS_FUNC_TYPE),
    ]

class IHostVtbl(ctypes.Structure):
    _fields_ = [("IUnknown", IUnknownVtbl), ("GetHostType", GET_HOST_TYPE_FUNC_TYPE), ("GetService", GET_SERVICE_FUNC_TYPE), ("GetCurrentTarget", GET_CURRENT_TARGET_FUNC_TYPE)]

class IMemoryService(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(IMemoryServiceVtbl))]

class IDebuggerServices(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(IDebuggerServicesVtbl))]

class IHost(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(IHostVtbl))]

class IHostServicesVtbl(ctypes.Structure):
    _fields_ = [
        ("IUnknown", IUnknownVtbl),
        ("GetHost", HOSTSERVICES_GETHOST),
        ("RegisterDebuggerServices", HOSTSERVICES_REGISTERDEBUGGER),
        ("CreateTarget", HOSTSERVICES_CREATETARGET),
        ("UpdateTarget", HOSTSERVICES_UPDATETARGET),
        ("FlushTarget", HOSTSERVICES_FLUSHTARGET),
        ("DestroyTarget", HOSTSERVICES_DESTROYTARGET),
        ("DispatchCommand", HOSTSERVICES_DISPATCHCOMMAND),
        ("Uninitialize", HOSTSERVICES_UNINITIALIZE),
    ]

class IHostServices(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(IHostServicesVtbl))]

class ILLDBServicesVtbl(ctypes.Structure):
    _fields_ = [
        ("IUnknown", IUnknownVtbl),
        ("GetCoreClrDirectory", ctypes.CFUNCTYPE(PCSTR, PVOID)),
        ("GetExpression", ctypes.CFUNCTYPE(ULONG64, PVOID, PCSTR)),
        ("VirtualUnwind", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG, PVOID)),
        ("SetExceptionCallback", ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID)),
        ("ClearExceptionCallback", ctypes.CFUNCTYPE(HRESULT, PVOID)),
        ("GetInterrupt", ctypes.CFUNCTYPE(HRESULT, PVOID)),
        ("OutputVaList", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, PVOID)),
        ("GetDebuggeeType", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))),
        ("GetPageSize", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))),
        ("GetProcessorType", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))),
        ("Execute", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ULONG)),
        ("GetLastEventInformation", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG), ctypes.POINTER(ULONG), PVOID, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG))),
        ("Disassemble", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ULONG, ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))),
        ("GetContextStackTrace", ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID, ULONG, PVOID, ULONG, PVOID, ULONG, ULONG, ctypes.POINTER(ULONG))),
        ("ReadVirtual", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))),
        ("WriteVirtual", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, PVOID, ULONG, ctypes.POINTER(ULONG))),
        ("GetSymbolOptions", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))),
        ("GetNameByOffset", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))),
        ("GetNumberModules", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))),
        ("GetModuleByIndex", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64))),
        ("GetModuleByModuleName", ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))),
        ("GetModuleByOffset", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))),
        ("GetModuleNames", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG), ctypes.c_void_p, ULONG, ctypes.POINTER(ULONG))),
        ("GetLineByOffset", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG64, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG), ctypes.POINTER(ULONG64))),
        ("GetSourceFileLineOffsets", ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ctypes.POINTER(ULONG64), ULONG, ctypes.POINTER(ULONG))),
        ("FindSourceFile", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, PCSTR, ULONG, ctypes.POINTER(ULONG), ctypes.c_char_p, ULONG, ctypes.POINTER(ULONG))),
        ("GetCurrentProcessSystemId", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))),
        ("GetCurrentThreadId", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))),
        ("SetCurrentThreadId", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG)),
        ("GetCurrentThreadSystemId", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG))),
        ("GetThreadIdBySystemId", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG))),
        ("GetThreadContextBySystemId", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG, ULONG, PVOID)),
        ("GetValueByName", ctypes.CFUNCTYPE(HRESULT, PVOID, PCSTR, ctypes.POINTER(ctypes.c_size_t))),
        ("GetInstructionOffset", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG64))),
        ("GetStackOffset", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG64))),
        ("GetFrameOffset", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.POINTER(ULONG64))),
    ]

class ILLDBServices(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(ILLDBServicesVtbl))]

class ILLDBServices2Vtbl(ctypes.Structure):
    _fields_ = [
        ("IUnknown", IUnknownVtbl),
        ("LoadNativeSymbols", ctypes.CFUNCTYPE(HRESULT, PVOID, ctypes.c_bool, PVOID)),
        ("AddModuleSymbol", ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID, PCSTR)),
        ("GetModuleInfo", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ctypes.POINTER(ULONG64), ctypes.POINTER(ULONG64), ctypes.POINTER(ULONG), ctypes.POINTER(ULONG))),
        ("GetModuleVersionInformation", ctypes.CFUNCTYPE(HRESULT, PVOID, ULONG, ULONG64, PCSTR, PVOID, ULONG, ctypes.POINTER(ULONG))),
        ("SetRuntimeLoadedCallback", ctypes.CFUNCTYPE(HRESULT, PVOID, PVOID)),
    ]

class ILLDBServices2(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(ILLDBServices2Vtbl))]
