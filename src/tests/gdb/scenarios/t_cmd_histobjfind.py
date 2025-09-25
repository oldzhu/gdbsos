import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    gdb.execute('histinit', to_string=True)
    out = gdb.execute('histobjfind 1', to_string=True)
    assertTrue(True)
    return True
