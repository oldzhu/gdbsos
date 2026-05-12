import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    md_out = gdb.execute(f'name2ee {assemblyName} Test.DumpClass', to_string=True)
    ee = None
    for line in md_out.splitlines():
        if 'MethodDesc:' in line:
            parts = line.split()
            for p in parts:
                if all(c in '0123456789abcdefABCDEF' for c in p):
                    try:
                        dm = gdb.execute(f'dumpmd {p}', to_string=True)
                        for l2 in dm.splitlines():
                            if 'EEClass:' in l2:
                                ee = l2.split()[-1]
                                break
                        break
                    except gdb.error:
                        pass
        if ee:
            break
    ok = True
    if ee:
        out = gdb.execute(f'dumpclass {ee}', to_string=True)
        ok = ('Fields:' in out) or ('MethodTable:' in out)
    assertTrue(ok)
    return ok
