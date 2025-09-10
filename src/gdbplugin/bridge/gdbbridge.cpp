// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "extensions.h"

// Mirror the LLDB plugin pattern: hold our own Extensions singleton in this DSO.
namespace {
class GdbPluginExtensions : public Extensions {
public:
    GdbPluginExtensions(IDebuggerServices* dbg) : Extensions(dbg) {}

    static void Initialize(IDebuggerServices* dbg) {
        if (s_extensions == nullptr) {
            s_extensions = new GdbPluginExtensions(dbg);
        }
    }

    IHost* GetHost() override {
        if (m_pHost == nullptr) {
            // Initialize the hosting runtime which will call InitializeHostServices
            // and provide a host instance via the callback.
            InitializeHosting();
        }
        return m_pHost;
    }
};
} // anonymous namespace

extern "C" {

static bool g_hostingInitialized = false;

__attribute__((visibility("default"))) int InitGdbExtensions(IDebuggerServices* debuggerServices)
{
    GdbPluginExtensions::Initialize(debuggerServices);
    return 0;
}

__attribute__((visibility("default"))) int InitManagedHosting(
    const char* runtimeDirectory,
    int majorVersion)
{
    // Ensure our local Extensions singleton exists before hosting
    if (Extensions::GetInstance() == nullptr) {
        return 0x80004002; // E_NOINTERFACE equivalent until InitGdbExtensions is called
    }
    if (g_hostingInitialized) {
        return 0; // already initialized
    }
    if (runtimeDirectory != nullptr || majorVersion != 0) {
        if (!SetHostRuntime(HostRuntimeFlavor::NetCore, majorVersion, /*minor*/0, runtimeDirectory)) {
            return 0x80004005;
        }
    }
    HRESULT hr = InitializeHosting();
    if (FAILED(hr)) {
        return (int)hr;
    }
    g_hostingInitialized = true;
    return 0;
}

__attribute__((visibility("default"))) int DispatchManagedCommand(
    const char* commandName,
    const char* arguments)
{
    IHostServices* hostServices = GetHostServices();
    if (hostServices == nullptr) {
        // Try to initialize hosting on-demand
        int hr = InitManagedHosting(nullptr, 0);
        if (hr != 0) {
            return hr;
        }
        hostServices = GetHostServices();
        if (hostServices == nullptr) {
            return 0x80004002; // E_NOINTERFACE
        }
    }
    return hostServices->DispatchCommand(commandName, arguments, /*displayCommandNotFound*/ true);
}

// Returns the IHost* pointer for passing to libsos SOSInitializeByHost.
__attribute__((visibility("default"))) void* GetHostForSos()
{
    if (Extensions::GetInstance() == nullptr) {
        return nullptr;
    }
    return (void*)Extensions::GetInstance()->GetHost();
}

// Force the managed host to update/create the target for the given process id.
// This helps ensure DebugServices sees the correct PID after runtime load.
__attribute__((visibility("default"))) int UpdateManagedTarget(unsigned int processId)
{
    // Ensure the Extensions singleton exists and managed hosting is initialized
    if (Extensions::GetInstance() == nullptr) {
        return 0x80004002; // E_NOINTERFACE until InitGdbExtensions is called
    }
    IHostServices* hostServices = GetHostServices();
    if (hostServices == nullptr) {
        int hr = InitManagedHosting(nullptr, 0);
        if (hr != 0) {
            return hr;
        }
    }
    HRESULT hrUpdate = Extensions::GetInstance()->UpdateTarget(processId);
    return (int)hrUpdate;
}

}
