import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('clrthreads', to_string=True)
    ok = ('ThreadID' in out) or ('DBG' in out) or (out.count('\n') > 2)
    assertTrue(ok)
    return ok
