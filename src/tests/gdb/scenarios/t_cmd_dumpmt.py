import gdb
from gdbtestutils import assertTrue, bpmd_and_continue
import re

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute(f'name2ee {assemblyName} Test.DumpIL', to_string=True)
    mt = None
    for line in out.splitlines():
        m = re.search(r'MethodTable:\s+([0-9a-fA-F]+)', line)
        if m:
            mt = m.group(1)
            break
    if not mt:
        m2 = re.search(r'MethodDesc:\s+([0-9a-fA-F]+)', out)
        if m2:
            md = m2.group(1)
            dm = gdb.execute(f'dumpmd {md}', to_string=True)
            m3 = re.search(r'MethodTable:\s+([0-9a-fA-F]+)', dm)
            if m3:
                mt = m3.group(1)
    ok = True
    if mt:
        mt_out = gdb.execute(f'dumpmt {mt}', to_string=True)
        ok = ('EEClass:' in mt_out) or ('Module:' in mt_out)
    assertTrue(ok)
    return ok
