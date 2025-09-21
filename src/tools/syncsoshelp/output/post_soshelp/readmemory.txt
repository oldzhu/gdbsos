(lldb) settings set target.disable-aslr true
(lldb) settings set auto-confirm true
(lldb) plugin load /workspaces/gdbsos/src/diagnostics/artifacts/bin/linux.x64.Debug/libsosplugin.so
(lldb) target create "/workspaces/gdbsos/src/diagnostics/artifacts/bin/SimpleThrow/Debug/net8.0/SimpleThrow"
Current executable set to '/workspaces/gdbsos/src/diagnostics/artifacts/bin/SimpleThrow/Debug/net8.0/SimpleThrow' (x86_64).
(lldb) process launch --stop-at-entry
Process 36402 launched: '/workspaces/gdbsos/src/diagnostics/artifacts/bin/SimpleThrow/Debug/net8.0/SimpleThrow' (x86_64)
(lldb) br set -r coreclr_execute_assembly
Breakpoint 1: no locations (pending).
WARNING:  Unable to resolve breakpoint to any actual locations.
(lldb) continue
1 location added to breakpoint 1
Process 36402 resuming
Process 36402 stopped
* thread #1, name = 'SimpleThrow', stop reason = breakpoint 1.1
    frame #0: 0x00007ffff6c88a91 libcoreclr.so`::coreclr_execute_assembly(hostHandle=0x00005555555ca1e0, domainId=1, argc=0, argv=0x0000000000000000, managedAssemblyPath="/workspaces/gdbsos/src/diagnostics/artifacts/bin/SimpleThrow/Debug/net8.0/SimpleThrow.dll", exitCode=0x00007fffffffd6e0) at exports.cpp:487:18
   484 	            const char* managedAssemblyPath,
   485 	            unsigned int* exitCode)
   486 	{
-> 487 	    if (exitCode == NULL)
    	                 ^
   488 	    {
   489 	        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
   490 	    }

(lldb) soshelp readmemory
Description:
  Dumps memory contents.

Usage:
  > d [<address>] [options]

Arguments:
  <address>  Address to dump.

Options:
  -e, --end         Ending address to dump.
  -c, --count       Number of elements to dump.
  -l, --length      Size of elements to dump.
  -w, --width       Number of elements to dump per row.
  -a, --ascii       Print ascii dump as well.
  -u, --unicode     Print unicode dump as well.
  --ascii-string    Print as ascii string as well.
  --unicode-string  Print as unicode string as well.
  -h, --hex-prefix  Add a hex prefix (0x) to the data displayed.
  --show-address    Display the addresses of data found.

(lldb) quit
