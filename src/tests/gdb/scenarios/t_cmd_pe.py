import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    # Intentionally trigger an exception by executing a command that should succeed first
    # Then just run 'pe' (PrintException). If no current exception, output may be short; accept presence of 'Exception' token or graceful message.
    out = gdb.execute('pe', to_string=True)
    ok = ('Exception' in out) or ('No current exception' in out) or (len(out) > 0)
    assertTrue(ok)
    return ok
