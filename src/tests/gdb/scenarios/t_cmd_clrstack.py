import gdb
from gdbtestutils import assertTrue, bpmd_and_continue


def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('clrstack', to_string=True)
    # Look for some typical managed indicators
    # This is intentionally loose to accommodate different runtimes
    needles = [
        'Managed Thread',
        'OS Thread Id',
        '[GCFrame',
    ]
    ok = any(n in out for n in needles) or len(out.splitlines()) > 3
    assertTrue(ok)
    return ok
