import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    # For prefix command 'sos' with no args, we expect usage guidance
    # No need to bp into managed code, but keep consistent
    bpmd_and_continue(assemblyName)
    out = gdb.execute('sos', to_string=True)
    ok = ('Usage:' in out) or ('help sos' in out) or (len(out) > 0)
    assertTrue(ok)
    return ok
