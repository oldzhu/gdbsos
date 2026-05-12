import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('gcwhere', to_string=True)
    ok = len(out.splitlines()) > 0
    assertTrue(ok)
    return ok
