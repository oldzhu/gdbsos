import gdb
from gdbtestutils import assertTrue, bpmd_and_continue
import re

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute(f'name2ee {assemblyName} Test.DumpIL', to_string=True)
    md = None
    for line in out.splitlines():
        m = re.search(r'MethodDesc:\s+([0-9a-fA-F]+)', line)
        if m:
            md = m.group(1)
            break
    ok = True
    if md:
        bp = gdb.execute(f'bpmd -md {md}', to_string=True)
        ok = len(bp) > 0
    assertTrue(ok)
    return ok
