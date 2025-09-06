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

# Comma/space separated categories, e.g. "bpmd,stop,newobj". If empty: all.
_cats_env = os.getenv("SOS_PY_TRACE_CATEGORIES", "")
TRACE_CATEGORIES = set(c.strip().lower() for c in _cats_env.replace(",", " ").split() if c.strip())
_DEFAULT_CAT = "misc"


def _trace_allowed(category: str) -> bool:
    if not TRACE_ENABLED:
        return False
    if not TRACE_CATEGORIES:
        return True
    return category.lower() in TRACE_CATEGORIES


def trace(msg: str):
    # Legacy trace: routed to default category 'misc'.
    if not _trace_allowed(_DEFAULT_CAT):
        return
    try:
        gdb.write(msg + "\n")
    except Exception:
        pass


def trace_cat(category: str, msg: str):
    if not _trace_allowed(category):
        return
    try:
        gdb.write(msg + "\n")
    except Exception:
        pass


class SOSTraceCommand(gdb.Command):
    """Toggle sos.py tracing.
    Usage:
        sostrace on [cats]    # enable tracing; optional comma/space list of categories
        sostrace off          # disable tracing
        sostrace status       # show status and categories
        sostrace cats         # list current categories
    Examples:
        sostrace on bpmd
        sostrace on bpmd,stop,newobj
    Categories are user-defined labels we emit from the plugin. If none are set, all traces show.
    """
    def __init__(self):
        super(SOSTraceCommand, self).__init__("sostrace", gdb.COMMAND_NONE)

    def invoke(self, arg, from_tty):
        global TRACE_ENABLED, TRACE_CATEGORIES
        a = (arg or "").strip()
        al = a.lower()
        if al == "cats":
            cats = ", ".join(sorted(TRACE_CATEGORIES)) if TRACE_CATEGORIES else "<all>"
            gdb.write(f"sostrace categories: {cats}\n")
            return
        if al in ("", "status"):
            cats = ", ".join(sorted(TRACE_CATEGORIES)) if TRACE_CATEGORIES else "<all>"
            gdb.write(f"sostrace: {'on' if TRACE_ENABLED else 'off'}; categories: {cats}\n")
            return
        if al.startswith("on"):
            # Allow: on, or on <cats>
            parts = a.split(None, 1)
            TRACE_ENABLED = True
            if len(parts) > 1:
                # parse categories
                raw = parts[1].replace(",", " ")
                TRACE_CATEGORIES = set(c.strip().lower() for c in raw.split() if c.strip())
            gdb.write("sostrace: on\n")
            return
        if al in ("off", "0", "false"):
            TRACE_ENABLED = False
            gdb.write("sostrace: off\n")
            return
        gdb.write("Usage: see 'help sostrace'\n")
