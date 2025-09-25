import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('dumpheap', to_string=True)
    ok = ('Address' in out) or (out.count('\n') > 5)
    assertTrue(ok)
    return ok
