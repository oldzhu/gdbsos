# FAQ and Troubleshooting

## Hosting initialization errors

- 0x80070057 (E_INVALIDARG) from coreclr_initialize
  - Commonly caused by relative paths in APP_PATHS/NATIVE_DLL_SEARCH_DIRECTORIES when the plugin is sourced via a relative path.
  - Fix: use an absolute path to the plugin directory. Current `sos.py` resolves its own path to absolute automatically; if issues persist, source with an absolute path:
    - `source /absolute/path/to/src/diagnostics/artifacts/bin/current/sos.py`

- 0x80131022 (HOST_E_INVALIDOPERATION)
  - Happens when hosting was already initialized in the same GDB process due to a prior attempt.
  - Fix: start a fresh GDB session and retry.

## Picking a runtime

- Prefer a stable shared runtime directory under DOTNET_ROOT:
  - `/.../.dotnet/shared/Microsoft.NETCore.App/8.0.x`
- Initialize explicitly if needed:
  - `sethostruntime -major 8 /.../Microsoft.NETCore.App/8.0.x`

## Symbols and DAC

- If `clrstack` reports DAC load issues, enable symbol servers or specify the path:
  - `setsymbolserver -ms`
  - `setclrpath <directory with libmscordaccore.so>`

## Long output and paging (e.g., `clru`)

- GDB’s pager captures large outputs.
  - Disable paging: `set pagination off`.
  - Capture to file: `set logging on` then run the command.
- Pressing `q` during paging may not cancel native printing from SOS; Ctrl-C interrupts GDB.
