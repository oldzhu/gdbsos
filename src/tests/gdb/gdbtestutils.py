"""Utilities imported inside the GDB process"""

import gdb
import importlib
import inspect
import os
import re
import time

# Two-phase async support
_assembly_name_cached = None
_skip_bpmd_and_continue = False

summary_file = ''
fail_flag = ''

_failed = False


def _append_stack(summary):
    for s in inspect.stack()[2:]:
        print("!!!  %s:%i" % (s[1], s[2]), file=summary)
        if s[4]:
            print("!!! %s" % s[4][0], file=summary)
        if re.match(r"\W*t_\w+\.py$", s[1]):
            break


def _assert_common(passed, fatal):
    global _failed
    with open(summary_file, 'a+') as summary:
        print(bool(passed), file=summary)
        if not passed:
            _failed = True
            print('!!! test failed:', file=summary)
            _append_stack(summary)
            print('!!! ', file=summary)
            if fatal:
                raise SystemExit(1)


def assertTrue(x, fatal=True):
    _assert_common(bool(x), fatal)


def assertFalse(x, fatal=True):
    _assert_common(not bool(x), fatal)


def assertEqual(x, y, fatal=True):
    _assert_common(x == y, fatal)


def assertNotEqual(x, y, fatal=True):
    _assert_common(x != y, fatal)


def bpmd_and_continue(assembly_name: str, method: str = 'Test.Main'):
    # Minimal flow to mirror LLDB stop_in_main, with detailed tracing
    def _trace(msg: str):
        try:
            gdb.write(f"[trace] {msg}\n")
        except Exception:
            pass

    def _exec_with_trace(cmd: str, label: str):
        _trace(f"exec: {cmd}")
        try:
            out = gdb.execute(cmd, to_string=True)
            if out:
                _trace(f"{label} output:\n{out}")
            else:
                _trace(f"{label} output: (no output)")
            return out
        except Exception as e:
            _trace(f"{label} exception: {e}")
            raise

    # If running in two-phase mode, skip bpmd/continue here; just assert we're stopped
    if _skip_bpmd_and_continue:
        try:
            frame = gdb.newest_frame()
        except gdb.error as e:
            _trace(f"newest_frame exception in skip-mode: {e}")
            frame = None
        assertTrue(frame is not None)
        return

    # Enable SOS internal tracing (categories: bpmd, stop, newobj)
    try:
        _exec_with_trace('sostrace on bpmd,stop,newobj', 'sostrace')
    except Exception:
        pass

    # Set the managed breakpoint and continue
    out = _exec_with_trace(f"bpmd {assembly_name} {method}", 'bpmd')
    assertTrue(len(out) > 0)

    try:
        _exec_with_trace('continue', 'continue')
    except gdb.error:
        time.sleep(0.05)
        _exec_with_trace('continue', 'continue(retry)')

    # Poll newest_frame for up to 30 minutes to observe the stop (extended diagnostics)
    deadline = time.time() + 1800.0
    frame = None
    first_error_logged = False
    while time.time() < deadline:
        try:
            frame = gdb.newest_frame()
            if frame is not None:
                break
        except gdb.error as e:
            if not first_error_logged:
                _trace(f"newest_frame exception: {e}")
                first_error_logged = True
        time.sleep(0.05)
    assertTrue(frame is not None)


def exit_gdb():
    try:
        gdb.execute('delete breakpoints', to_string=True)
    except gdb.error:
        pass
    try:
        gdb.execute('continue', to_string=True)
    except gdb.error:
        # Process may already be exited
        pass


def run(host, assembly, scenario_module):
    # Setup stable GDB settings for non-interactive runs
    gdb.execute('set pagination off', to_string=True)
    gdb.execute('set confirm off', to_string=True)
    gdb.execute('set breakpoint pending on', to_string=True)

    # Set breakpoint and launch the managed process under host
    gdb.execute('break coreclr_execute_assembly', to_string=True)
    gdb.execute(f'file {host}', to_string=True)
    gdb.execute(f'set args {assembly}', to_string=True)
    # Prepare assembly name for managed bpmd
    assembly_name = os.path.basename(assembly)
    gdb.execute('run', to_string=True)

    # Import and run the scenario with per-command tracing
    mod = importlib.import_module(scenario_module)
    scenario_file = None
    try:
        scenario_file = os.path.abspath(getattr(mod, '__file__', '') or '')
    except Exception:
        scenario_file = None
    _orig_execute = gdb.execute
    def _scenario_exec(cmd: str, to_string: bool = False):
        should_log = False
        try:
            for fr in inspect.stack()[1:]:
                fn = getattr(fr, 'filename', None) or (fr[1] if isinstance(fr, tuple) and len(fr) > 1 else None)
                if fn and scenario_file and os.path.abspath(fn) == scenario_file:
                    should_log = True
                    break
        except Exception:
            pass
        if should_log:
            try:
                gdb.write(f"[scenario] exec: {cmd}\n")
            except Exception:
                pass
        out = _orig_execute(cmd, to_string=to_string)
        if should_log and to_string:
            try:
                if out:
                    gdb.write(f"[scenario] output:\n{out}")
                else:
                    gdb.write("[scenario] output: (no output)\n")
            except Exception:
                pass
        return out
    gdb.execute = _scenario_exec
    try:
        result = mod.runScenario(assembly_name)
    finally:
        gdb.execute = _orig_execute

    # On success, delete the fail flag so the outer runner knows we passed
    if result and not _failed:
        try:
            os.unlink(fail_flag)
        except Exception:
            pass

    return result


# prepare_phase and verify_phase have been removed; schedule_and_run supersedes them.


def schedule_and_run(host, assembly, scenario_module, method: str = 'Test.Main'):
    """Event-driven flow: launch + bpmd, then install a one-shot stop handler
    that will run the scenario at the next real stop (e.g., after bpmd hits),
    and then quit GDB. Use with a subsequent CLI 'continue' in -batch mode.
    """
    global _assembly_name_cached

    def _trace(msg: str):
        try:
            gdb.write(f"[trace] {msg}\n")
        except Exception:
            pass

    def _exec(label: str, cmd: str, to_string: bool = True):
        _trace(f"exec: {cmd}")
        try:
            out = gdb.execute(cmd, to_string=to_string)
            if to_string:
                _trace(f"{label} output:\n{out}" if out else f"{label} output: (no output)")
            return out
        except Exception as ex:
            _trace(f"{label} exception: {ex}")
            raise

    # Launch to coreclr entry
    _exec('set pagination', 'set pagination off')
    _exec('set confirm', 'set confirm off')
    _exec('set pending', 'set breakpoint pending on')
    _exec('break entry', 'break coreclr_execute_assembly')
    _exec('file', f'file {host}')
    _exec('set args', f'set args {assembly}')
    _assembly_name_cached = os.path.basename(assembly)
    _exec('run', 'run')

    try:
        _exec('sostrace', 'sostrace on bpmd,stop,newobj')
    except Exception:
        pass

    # Prime bpmd and then immediately continue
    _exec('bpmd', f'bpmd {_assembly_name_cached} {method}')
    def _do_continue():
        try:
            _exec('continue', 'continue')
        except Exception:
            pass
    _do_continue()

    def _trace(msg: str):
        try:
            gdb.write(f"[trace] {msg}\n")
        except Exception:
            pass

    def _pc_matches_cli_bp(pc: int) -> bool:
        try:
            bps = gdb.breakpoints() or []
        except Exception:
            bps = []
        for bp in bps:
            try:
                loc = getattr(bp, 'location', '') or ''
                if loc.startswith('*0x'):
                    try:
                        addr = int(loc[1:], 16)  # strip leading '*'
                        if addr == pc:
                            return True
                    except Exception:
                        continue
            except Exception:
                continue
        return False

    # Stop handler that only fires the scenario at the bpmd JIT bp; otherwise keep running
    def _on_stop(event):
        _trace('[handler] on_stop: entered')
        # Thread and event info
        try:
            thr = gdb.selected_thread()
            if thr:
                _trace(f"[handler] thread num={thr.num} ptid={getattr(thr, 'ptid', None)}")
        except Exception as ex:
            _trace(f"[handler] selected_thread ex: {ex}")

        pc = None
        try:
            pc = gdb.selected_frame().pc()
            _trace(f"[handler] pc=0x{pc:x}")
        except Exception as ex:
            _trace(f"[handler] selected_frame().pc ex: {ex}")

        # Dump CLI-style *0x... breakpoints for visibility
        try:
            bps = gdb.breakpoints() or []
            cli_bps = []
            for bp in bps:
                try:
                    loc = getattr(bp, 'location', '') or ''
                    if loc.startswith('*0x'):
                        cli_bps.append(loc)
                except Exception:
                    continue
            _trace(f"[handler] cli-bps={cli_bps}")
        except Exception as ex:
            _trace(f"[handler] breakpoints() ex: {ex}")

        if pc is None or not _pc_matches_cli_bp(pc):
            _trace('[handler] stop ignored (not at bpmd jit bp)')
            return

        # Disconnect now that we've reached the desired stop
        try:
            gdb.events.stop.disconnect(_on_stop)
            _trace('[handler] disconnected from gdb.events.stop')
        except Exception:
            _trace('[handler] disconnect raised (ignored)')

        # Run the scenario with skip flag so it only asserts we're stopped,
        # then executes its commands (e.g., 'pe')
        global _skip_bpmd_and_continue
        _skip_bpmd_and_continue = True
        try:
            _trace('[handler] running scenario.start')
            # Wrap gdb.execute to trace scenario commands and outputs
            _orig_execute = gdb.execute
            def _scenario_exec(cmd: str, to_string: bool = False):
                try:
                    gdb.write(f"[scenario] exec: {cmd}\n")
                except Exception:
                    pass
                out = _orig_execute(cmd, to_string=to_string)
                if to_string:
                    try:
                        if out:
                            gdb.write(f"[scenario] output:\n{out}")
                        else:
                            gdb.write("[scenario] output: (no output)\n")
                    except Exception:
                        pass
                return out
            gdb.execute = _scenario_exec
            mod = importlib.import_module(scenario_module)
            scenario_file = None
            try:
                scenario_file = os.path.abspath(getattr(mod, '__file__', '') or '')
            except Exception:
                scenario_file = None
            result = mod.runScenario(_assembly_name_cached)
            _trace(f"[handler] scenario.done result={result} failed={_failed}")
            if result and not _failed:
                try:
                    os.unlink(fail_flag)
                except Exception:
                    pass
        finally:
            # Restore original gdb.execute and clear flag
            try:
                gdb.execute = _orig_execute
            except Exception:
                pass
            _skip_bpmd_and_continue = False
            _trace('[handler] skip flag cleared')

        # Exit GDB to finish batch
        try:
            _trace('[handler] issuing quit')
            gdb.execute('quit', to_string=False)
        except Exception:
            _trace('[handler] quit raised (ignored)')

    gdb.events.stop.connect(_on_stop)
    _trace('[handler] connected to gdb.events.stop')


"""register_stop_handler has been removed; schedule_and_run installs its own filtered handler."""
