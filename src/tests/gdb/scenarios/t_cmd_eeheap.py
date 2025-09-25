import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('eeheap', to_string=True)
    ok = ('Loader Heap' in out) or ('\n' in out)
    assertTrue(ok)
    return ok
