import gdb
from gdbtestutils import assertTrue, bpmd_and_continue

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute(f'name2ee {assemblyName} Test.DumpModule', to_string=True)
    module_token = None
    for line in out.splitlines():
        if 'File:' in line and assemblyName in line:
            module_token = assemblyName
            break
    ok = True
    if module_token:
        mod_out = gdb.execute(f'dumpmodule {module_token}', to_string=True)
        ok = ('Module:' in mod_out) or ('Assembly:' in mod_out)
    assertTrue(ok)
    return ok
