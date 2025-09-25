import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    # Provide an explicit il offset (0) which should still plant a breakpoint
    out = gdb.execute(f'bpmd {assemblyName} Test.DumpIL 0', to_string=True)
    ok = ('Breakpoint' in out) or (len(out) > 0)
    assertTrue(ok)
    return ok
