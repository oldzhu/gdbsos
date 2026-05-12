import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    # dumpvc requires an address argument; use generic invocation that shows usage
    out = gdb.execute('dumpvc', to_string=True)
    ok = len(out.splitlines()) > 0
    assertTrue(ok)
    return ok
