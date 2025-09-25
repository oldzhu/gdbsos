import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    # name2ee <assembly> <Type.Method>
    out = gdb.execute(f'name2ee {assemblyName} Test.DumpIL', to_string=True)
    ok = ('MethodDesc:' in out) and ('Test.DumpIL' in out)
    assertTrue(ok)
    return ok
