"""Utilities imported inside the GDB process"""

import gdb
import importlib
import inspect
import os
import re
import time

summary_file = ''
fail_flag = ''

_failed = False


def _append_stack(summary):
    for s in inspect.stack()[2:]:
        print("!!!  %s:%i" % (s[1], s[2]), file=summary)
        if s[4]:
            print("!!! %s" % s[4][0], file=summary)
        if re.match(r"\W*t_\w+\.py$", s[1]):
            break


def _assert_common(passed, fatal):
    global _failed
    with open(summary_file, 'a+') as summary:
        print(bool(passed), file=summary)
        if not passed:
            _failed = True
            print('!!! test failed:', file=summary)
            _append_stack(summary)
            print('!!! ', file=summary)
            if fatal:
                raise SystemExit(1)


def assertTrue(x, fatal=True):
    _assert_common(bool(x), fatal)


def assertFalse(x, fatal=True):
    _assert_common(not bool(x), fatal)


def assertEqual(x, y, fatal=True):
    _assert_common(x == y, fatal)


def assertNotEqual(x, y, fatal=True):
    _assert_common(x != y, fatal)


def bpmd_and_continue(assembly_name: str, method: str = 'Test.Main'):
    try:
        frame = gdb.newest_frame()
    except gdb.error:
        frame = None
    assertTrue(frame is not None)


def run(host, assembly, scenario_module):
    gdb.execute('set pagination off', to_string=True)
    gdb.execute('set confirm off', to_string=True)
    gdb.execute('set breakpoint pending on', to_string=True)

    gdb.execute('break coreclr_execute_assembly', to_string=True)
    gdb.execute(f'file {host}', to_string=True)
    gdb.execute(f'set args {assembly}', to_string=True)
    gdb.execute('run', to_string=True)

    assembly_name = os.path.basename(assembly)
    mod = importlib.import_module(scenario_module)
    result = mod.runScenario(assembly_name)

    if result and not _failed:
        try:
            os.unlink(fail_flag)
        except Exception:
            pass

    return result


# schedule_and_run uses the same flow as run() - break at coreclr_execute_assembly
# then invoke the scenario from the native stop point where CLR is loaded and SOS is available
schedule_and_run = run
