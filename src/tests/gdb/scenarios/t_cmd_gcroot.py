import gdb
from gdbtestutils import assertTrue, bpmd_and_continue
import re

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    # Use dso to find an object, then run gcroot
    dso = gdb.execute('dso', to_string=True)
    obj_addr = None
    for line in dso.splitlines():
        m = re.match(r'([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s', line)
        if m:
            obj_addr = m.group(2)
            break
    assertTrue(obj_addr is not None)
    out = gdb.execute(f'gcroot {obj_addr}', to_string=True)
    # Accept either a path printed or message that root not found but command succeeded.
    ok = ('Scan Depth' in out) or ('No roots found' in out) or (out.count('\n') > 3)
    assertTrue(ok)
    return ok
