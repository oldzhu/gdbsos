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

# Include list: only these categories are shown when non-empty.
_cats_env = os.getenv("SOS_PY_TRACE_CATEGORIES", "")
TRACE_CATEGORIES = set(c.strip().lower() for c in _cats_env.replace(",", " ").split() if c.strip())

# Exclude list: categories that are always suppressed.
_xcats_env = os.getenv("SOS_PY_TRACE_EXCLUDE", "")
TRACE_EXCLUDE_CATEGORIES = set(c.strip().lower() for c in _xcats_env.replace(",", " ").split() if c.strip())

# By default, suppress noisy categories unless explicitly allowed at runtime
# Users can enable them with:
#   - sostrace allow read|output|interrupt
#   - or by removing them from the exclude set in their environment before sourcing
_DEFAULT_SUPPRESS = {"read", "output", "interrupt"}
TRACE_EXCLUDE_CATEGORIES |= _DEFAULT_SUPPRESS

_DEFAULT_CAT = "misc"


def _trace_allowed(category: str) -> bool:
    if not TRACE_ENABLED:
        return False
    c = (category or "").lower()
    # Excludes always win
    if c in TRACE_EXCLUDE_CATEGORIES:
        return False
    # If include list is set, only allow those
    if TRACE_CATEGORIES:
        return c in TRACE_CATEGORIES
    # Otherwise allow all
    return True


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
        sostrace on [cats]        # enable tracing; optional comma/space list of include categories
        sostrace off              # disable all tracing
        sostrace off <cats>       # keep tracing on but suppress specific categories
        sostrace allow <cats>     # remove categories from the suppress (exclude) list
        sostrace status           # show status and include/exclude categories
        sostrace cats             # list current include categories (or <all> if none)
    Examples:
        sostrace on bpmd
        sostrace on bpmd,stop,newobj
        sostrace off read         # suppress noisy 'read' traces while keeping others
        sostrace allow read       # re-allow 'read' traces
    Notes:
        - Include list (on [cats]) acts as a whitelist. When set, only those categories are traced.
        - Exclude list (off <cats>) always suppresses those categories, even if included.
        - If no include list is set, all categories are traced except those explicitly excluded.
    """
    def __init__(self):
        super(SOSTraceCommand, self).__init__("sostrace", gdb.COMMAND_NONE)

    def invoke(self, arg, from_tty):
        global TRACE_ENABLED, TRACE_CATEGORIES, TRACE_EXCLUDE_CATEGORIES
        a = (arg or "").strip()
        al = a.lower()
        if al == "cats":
            cats = ", ".join(sorted(TRACE_CATEGORIES)) if TRACE_CATEGORIES else "<all>"
            gdb.write(f"sostrace include: {cats}\n")
            xcats = ", ".join(sorted(TRACE_EXCLUDE_CATEGORIES)) if TRACE_EXCLUDE_CATEGORIES else "<none>"
            gdb.write(f"sostrace exclude: {xcats}\n")
            return
        if al in ("", "status"):
            cats = ", ".join(sorted(TRACE_CATEGORIES)) if TRACE_CATEGORIES else "<all>"
            xcats = ", ".join(sorted(TRACE_EXCLUDE_CATEGORIES)) if TRACE_EXCLUDE_CATEGORIES else "<none>"
            gdb.write(f"sostrace: {'on' if TRACE_ENABLED else 'off'}; include: {cats}; exclude: {xcats}\n")
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
        if al.startswith("off") or al in ("0", "false"):
            # Allow: off, or off <cats>
            parts = a.split(None, 1)
            if len(parts) == 1 or al in ("0", "false"):
                TRACE_ENABLED = False
                gdb.write("sostrace: off\n")
                return
            # off <cats>: add to exclude list without disabling tracing
            raw = parts[1].replace(",", " ")
            cats = set(c.strip().lower() for c in raw.split() if c.strip())
            # merge
            before = set(TRACE_EXCLUDE_CATEGORIES)
            TRACE_EXCLUDE_CATEGORIES |= cats
            added = sorted(TRACE_EXCLUDE_CATEGORIES - before)
            if added:
                gdb.write("sostrace: excluded " + ", ".join(added) + "\n")
            else:
                gdb.write("sostrace: exclude unchanged\n")
            return
        if al.startswith("allow"):
            # allow <cats>: remove from exclude list
            parts = a.split(None, 1)
            if len(parts) == 1:
                gdb.write("Usage: sostrace allow <cats>\n")
                return
            raw = parts[1].replace(",", " ")
            cats = set(c.strip().lower() for c in raw.split() if c.strip())
            before = set(TRACE_EXCLUDE_CATEGORIES)
            TRACE_EXCLUDE_CATEGORIES -= cats
            removed = sorted(before - TRACE_EXCLUDE_CATEGORIES)
            if removed:
                gdb.write("sostrace: allowed " + ", ".join(removed) + "\n")
            else:
                gdb.write("sostrace: allow unchanged\n")
            return
        gdb.write("Usage: see 'help sostrace'\n")
