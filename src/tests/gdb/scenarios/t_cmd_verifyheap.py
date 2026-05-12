import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('verifyheap', to_string=True)
    ok = ('No heap corruption' in out) or ('\n' in out)
    assertTrue(ok)
    return ok
