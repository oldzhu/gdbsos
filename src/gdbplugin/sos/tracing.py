import os
import gdb


def _parse_bool_env(val: str, default: bool = False) -> bool:
    if val is None:
        return default
    v = str(val).strip().lower()
    if v in ("1", "true", "yes", "on"): return True
    if v in ("0", "false", "no", "off"): return False
    return default


TRACE_ENABLED = _parse_bool_env(os.getenv("SOS_PY_TRACE"), False)


def trace(msg: str):
    if not TRACE_ENABLED:
        return
    try:
        gdb.write(msg + "\n")
    except Exception:
        pass


class SOSTraceCommand(gdb.Command):
    """Toggle sos.py tracing. Usage: sostrace [on|off|status]"""
    def __init__(self):
        super(SOSTraceCommand, self).__init__("sostrace", gdb.COMMAND_NONE)

    def invoke(self, arg, from_tty):
        global TRACE_ENABLED
        a = (arg or "").strip().lower()
        if a in ("on", "1", "true"):
            TRACE_ENABLED = True
        elif a in ("off", "0", "false"):
            TRACE_ENABLED = False
        elif a in ("", "status"):
            pass
        else:
            gdb.write("Usage: sostrace [on|off|status]\n")
            return
        gdb.write(f"sostrace: {'on' if TRACE_ENABLED else 'off'}\n")
