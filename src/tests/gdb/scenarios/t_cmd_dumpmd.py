import gdb
from gdbtestutils import assertTrue, bpmd_and_continue
import re

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute(f'name2ee {assemblyName} Test.DumpMD', to_string=True)
    md = None
    for line in out.splitlines():
        m = re.search(r'MethodDesc:\s+([0-9a-fA-F]+)', line)
        if m:
            md = m.group(1)
            break
    ok = False
    if md:
        md_out = gdb.execute(f'dumpmd {md}', to_string=True)
        ok = ('MethodTable:' in md_out) or ('Class:' in md_out)
    assertTrue(ok)
    return ok
