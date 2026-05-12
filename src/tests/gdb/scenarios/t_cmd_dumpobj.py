import gdb
from gdbtestutils import assertTrue, bpmd_and_continue
import re

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    dso = gdb.execute('dso', to_string=True)
    obj_addr = None
    for line in dso.splitlines():
        m = re.match(r'([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s', line)
        if m:
            obj_addr = m.group(2)
            break
    ok = True
    if obj_addr:
        out = gdb.execute(f'dumpobj {obj_addr}', to_string=True)
        ok = ('MethodTable:' in out) or ('EEClass:' in out) or ('Size:' in out)
    assertTrue(ok)
    return ok
