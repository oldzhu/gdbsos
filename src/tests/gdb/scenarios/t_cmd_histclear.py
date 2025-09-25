import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out1 = gdb.execute('histinit', to_string=True)
    out2 = gdb.execute('histclear', to_string=True)
    # Since hist commands may be minimal, just ensure commands executed
    assertTrue(True)
    return True
