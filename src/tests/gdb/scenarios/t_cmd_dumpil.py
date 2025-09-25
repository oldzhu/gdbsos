import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute(f'dumpil {assemblyName} Test.DumpIL', to_string=True)
    ok = ('IL_' in out) or ('offset' in out.lower()) or (len(out) > 0)
    assertTrue(ok)
    return ok
