import gdb
from gdbtestutils import assertTrue, bpmd_and_continue
import re

def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('dumpdelegate', to_string=True)
    ok = len(out.splitlines()) > 0
    assertTrue(ok)
    return ok
