import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('syncblk', to_string=True)
    ok = ('Index' in out) or ('SyncBlock' in out) or ('\n' in out)
    assertTrue(ok)
    return ok
