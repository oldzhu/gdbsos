import gdb
from gdbtestutils import assertTrue, bpmd_and_continue
import re

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    # Get stack objects
    dso = gdb.execute('dso', to_string=True)
    # Find first object address (second hex group typically object addr)
    obj_addr = None
    for line in dso.splitlines():
        m = re.match(r'([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s', line)
        if m:
            obj_addr = m.group(2)
            break
    assertTrue(obj_addr is not None)
    out = gdb.execute(f'dumpobj {obj_addr}', to_string=True)
    ok = ('MethodTable:' in out) and ('EEClass:' in out) and ('Size:' in out)
    assertTrue(ok)
    return ok
