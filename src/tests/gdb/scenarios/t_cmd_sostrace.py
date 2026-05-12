import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('sostrace status', to_string=True)
    ok = ('sostrace' in out) and ('off' in out.lower() or 'on' in out.lower())
    assertTrue(ok)
    return ok
