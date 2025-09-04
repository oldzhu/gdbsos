import gdb
from gdbtestutils import assertTrue, bpmd_and_continue


def runScenario(assemblyName):
    bpmd_and_continue(assemblyName)
    out = gdb.execute('dso', to_string=True)
    # Expect SP/REG header present similar to LLDB expectations
    ok = ("SP/REG" in out) or (assemblyName in out)
    assertTrue(ok)
    return ok
