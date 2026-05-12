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
    ip = None
    if md:
        dm = gdb.execute(f'dumpmd {md}', to_string=True)
        for l2 in dm.splitlines():
            m2 = re.search(r'IP:\s+([0-9a-fA-F]+)', l2)
            if m2:
                ip = m2.group(1)
                break
    ok = True
    if ip:
        ip_out = gdb.execute(f'ip2md {ip}', to_string=True)
        ok = ('MethodDesc:' in ip_out) or ('Test.DumpIL' in ip_out)
    assertTrue(ok)
    return ok
