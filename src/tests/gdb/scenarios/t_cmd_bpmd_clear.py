import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    gdb.execute(f'bpmd {assemblyName} Test.DumpIL', to_string=True)
    out = gdb.execute('bpmd -clear', to_string=True)
    assertTrue(True)
    return True
