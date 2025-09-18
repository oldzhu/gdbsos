import gdb
from gdbtestutils import assertTrue


from gdbtestutils import bpmd_and_continue


def runScenario(assemblyName):
    # Stop in Test.Main to ensure managed commands are ready
    bpmd_and_continue(assemblyName)
    # Run soshelp and expect managed help to list several commands
    out = gdb.execute('soshelp', to_string=True)
    # Look for a couple of common managed commands
    needles = [
        'clrstack',
        'dso',
        'dumpobj',
    ]
    ok = all(n in out for n in needles)
    assertTrue(ok)
    return ok
