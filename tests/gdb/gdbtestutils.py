# Utilities imported inside the GDB process

import gdb
import importlib
import inspect
import os
import re

summary_file = ''
fail_flag = ''

_failed = False


def _append_stack(summary):
    for s in inspect.stack()[2:]:
        print("!!!  %s:%i" % (s[1], s[2]), file=summary)
        src = s[4][0] if s[4] else ''
        print("!!! %s" % src, file=summary)
        if re.match(r'\W*t_\w+\.py$', s[1] or ''):
            break
    print('!!! ', file=summary)


def _assert_common(passed, fatal):
    global _failed
    with open(summary_file, 'a+') as summary:
        print(bool(passed), file=summary)
        if not passed:
            _failed = True
            print('!!! test failed:', file=summary)
            _append_stack(summary)
            if fatal:
                # Force GDB to exit with failure
                raise gdb.GdbError('Assertion failed')


def assertTrue(x, fatal=True):
    _assert_common(bool(x), fatal)


def assertFalse(x, fatal=True):
    _assert_common(not bool(x), fatal)


def assertEqual(x, y, fatal=True):
    _assert_common(x == y, fatal)


def assertNotEqual(x, y, fatal=True):
    _assert_common(x != y, fatal)


def exec_and_find(cmd, regexp):
    out = gdb.execute(cmd, to_string=True)
    expr = re.compile(regexp)
    addr = None
    for line in out.splitlines():
        m = expr.match(line)
        if m:
            addr = m.group(1)
            break
    return addr


def bpmd_and_continue(assembly_name: str, method: str = 'Test.Main'):
    # Try to resolve MethodDesc first for reliable bpmd
    md = None
    try:
        out = gdb.execute(f"name2ee {assembly_name} {method}", to_string=True)
        m = re.search(r"MethodDesc:\s+([0-9a-fA-F]+)", out)
        if m:
            md = m.group(1)
    except gdb.error:
        md = None

    if md:
        out = gdb.execute(f"bpmd -md {md}", to_string=True)
    else:
        out = gdb.execute(f"bpmd {assembly_name} {method}", to_string=True)
    assertTrue(len(out) > 0)
    try:
        gdb.execute('continue', to_string=True)
    except gdb.error:
        assertTrue(False)
    # If we hit something, there should be a frame
    try:
        frame = gdb.newest_frame()
        assertTrue(frame is not None)
    except gdb.error:
        assertTrue(False)


def exit_gdb():
    try:
        gdb.execute('delete breakpoints', to_string=True)
    except gdb.error:
        pass
    try:
        gdb.execute('continue', to_string=True)
    except gdb.error:
        # Process may already be exited
        pass


def run(host, assembly, scenario_module):
    # Mark this GDB instance as progressed
    # The outer runner expects to see this file created before scenario starts
    # This is done by the outer command, not here.

    # Setup stable GDB settings for non-interactive runs
    gdb.execute('set pagination off', to_string=True)
    gdb.execute('set confirm off', to_string=True)
    gdb.execute('set breakpoint pending on', to_string=True)

    # Set breakpoint and launch the managed process under host
    gdb.execute('break coreclr_execute_assembly', to_string=True)
    gdb.execute(f'file {host}', to_string=True)
    gdb.execute(f'set args {assembly}', to_string=True)
    # Prepare assembly name for managed bpmd
    assembly_name = os.path.basename(assembly)
    gdb.execute('run', to_string=True)

    # Import and run the scenario
    mod = importlib.import_module(scenario_module)
    result = mod.runScenario(assembly_name)

    # On success, delete the fail flag so the outer runner knows we passed
    if result and not _failed:
        try:
            os.unlink(fail_flag)
        except Exception:
            pass

    return result
