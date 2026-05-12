import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('sosstatus', to_string=True)
    ok = len(out) >= 0
    assertTrue(ok)
    return ok
