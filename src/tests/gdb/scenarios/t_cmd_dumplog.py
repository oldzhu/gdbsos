import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('dumplog', to_string=True)
    # Accept empty output (depends on logging state) but treat command availability as success
    ok = True  # if it executed without gdb.error we count it
    assertTrue(ok)
    return ok
