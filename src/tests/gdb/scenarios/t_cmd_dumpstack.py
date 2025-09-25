import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('dumpstack', to_string=True)
    ok = ('OS Thread Id' in out) or (out.count('\n') > 3)
    assertTrue(ok)
    return ok
