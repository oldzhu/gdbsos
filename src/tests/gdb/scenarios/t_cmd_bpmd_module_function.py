import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    # Basic bpmd by module method; rely on helper for initial break so we can plant a second one
    bpmd_and_continue(assemblyName)
    out = gdb.execute(f'bpmd {assemblyName} Test.DumpIL', to_string=True)
    ok = ('Breakpoint' in out) or ('bpmd' in out.lower())
    assertTrue(ok)
    return ok
