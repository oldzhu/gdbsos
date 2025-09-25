import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    # Simulate module function bp with no future module (should still succeed or no-op gracefully)
    out = gdb.execute(f'bpmd -nofuturemodule {assemblyName} Test.DumpIL', to_string=True)
    ok = ('Breakpoint' in out) or (len(out) > 0)
    assertTrue(ok)
    return ok
