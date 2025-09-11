# hang_capture.gdb - automated data collection for CLRDataCreateInstance DAC hang
# Usage examples:
#   gdb -q -x scripts/hang_capture.gdb --args ./yourhost yourargs
#   (or within existing gdb) source scripts/hang_capture.gdb
# Optional environment before launching:
#   export SOS_TRACING=1

set pagination off
set confirm off
set breakpoint pending on

# Improve backtrace detail
set print frame-arguments all
set print pretty on
set print elements 200

# Try to load symbols lazily (user can adjust)
set auto-load safe-path /

# Where to log output (will append). You can change via: set $cap_log = "path"
set $cap_log = "hang_capture.log"

python
import datetime, gdb
fname = gdb.parse_and_eval('$cap_log').string()
with open(fname, 'a') as f:
    f.write('\n===== Hang capture session start: %s =====\n' % datetime.datetime.utcnow().isoformat())
end

# Break before the suspected hang entry. Adjust symbol variations.
b CLRDataCreateInstance
# Windows-style decorated alternative is unlikely here; for DAC internal getenv usage set below.

# Also break on GetEnvironmentVariableA inside DAC/pal to step/record
# The symbol might reside in libc or PAL; set multiple breakpoints defensively.
b GetEnvironmentVariableA
b getenv

# When hitting CLRDataCreateInstance, run some scripted logging.
python
import gdb, datetime
class CdiHook(gdb.Command):
    def __init__(self):
        super(CdiHook, self).__init__('cdi_hook', gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        pass
CdiHook()
end

define hook-stop
    # If at CLRDataCreateInstance entry
    if (strcmp($func, "CLRDataCreateInstance") == 0)
        printf "[hang-capture] Hit CLRDataCreateInstance at %p\n", $pc
        set $log = $cap_log
        shell echo "--- Break: CLRDataCreateInstance $(date -u +%Y-%m-%dT%H:%M:%SZ) ---" >> $log
        shell echo "Function: CLRDataCreateInstance" >> $log
        shell echo "Thread: $(/bin/echo -n $(info threads | wc -l)) total" >> $log
        info registers >> $log
        bt full >> $log
        # Continue to observe potential hang inside
        continue
    end
    if (strcmp($func, "GetEnvironmentVariableA") == 0) || (strcmp($func, "getenv") == 0)
        printf "[hang-capture] At env lookup %p\n", $pc
        set $log = $cap_log
        shell echo "--- Break: getenv variant $(date -u +%Y-%m-%dT%H:%M:%SZ) ---" >> $log
        bt 15 >> $log
        continue
    end
end

# Define a manual macro to dump everything once hang suspected
define dump_all
    set $log = $cap_log
    echo Collecting comprehensive diagnostics to $log\n
    shell echo "--- DUMP_ALL $(date -u +%Y-%m-%dT%H:%M:%SZ) ---" >> $log
    shell echo "[sections]" >> $log
    maint info sections >> $log

    shell echo "[threads backtraces full]" >> $log
    thread apply all bt full >> $log

    shell echo "[inferiors]" >> $log
    info inferiors >> $log

    shell echo "[shared libraries]" >> $log
    info sharedlibrary >> $log

    shell echo "[mapped files (/proc)]" >> $log
    shell cat /proc/`pidof $(basename $(readlink /proc/self/exe))`/maps >> $log 2>/dev/null

    shell echo "[loaded sos/dac search]" >> $log
    info files >> $log

    shell echo "[registers current thread]" >> $log
    info registers >> $log

    shell echo "[environment snapshot]" >> $log
    shell /usr/bin/env | sort >> $log

    shell echo "--- END DUMP_ALL ---" >> $log
end

# User can call: dump_all  when hang observed

define hang_watchdog
    set $log = $cap_log
    echo Starting hang watchdog (60s)\n
    while 1
        shell sleep 5
        # Heuristic: if stopped at prompt for >60s inside DAC, do capture
        if (strcmp($func, "CLRDataCreateInstance") == 0)
            shell echo "[watchdog] Still inside CLRDataCreateInstance $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> $log
        end
    end
end

# Provide a short help banner
python
import gdb
banner = """
[hang_capture.gdb loaded]
Commands/macros:
  dump_all          -> Capture comprehensive diagnostics now
  hang_watchdog &   -> (Optional) Run simple loop logging periodic status
Breakpoints set: CLRDataCreateInstance, GetEnvironmentVariableA, getenv
Log file: %s
Use 'continue' to run program.
""" % gdb.parse_and_eval('$cap_log').string()
print(banner)
end
