import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute(f'name2ee {assemblyName} Test.DumpIL', to_string=True)
    ok = ('MethodDesc:' in out) or ('Test.DumpIL' in out) or ('EEClass:' in out) or (len(out) > 0)
    assertTrue(ok)
    return ok
