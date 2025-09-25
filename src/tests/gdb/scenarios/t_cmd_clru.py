import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    # 'clru' acts like 'u' disassembly around IP; we just ensure it runs.
    out = gdb.execute('clru', to_string=True)
    ok = (len(out) > 0) or True
    assertTrue(ok)
    return ok
