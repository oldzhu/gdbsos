#!/usr/bin/env python3
# Lightweight GDB-based test harness for the SOS GDB plugin

import argparse
import inspect
import os
import re
import subprocess
import sys
import threading

tests_failed = False

def run_with_timeout(cmd, timeout, summary_file):
    p = None

    def run():
        nonlocal p
        p = subprocess.Popen(cmd, shell=True)
        p.communicate()

    t = threading.Thread(target=run)
    t.start()
    t.join(timeout)
    if t.is_alive():
        with open(summary_file, 'a+') as summary:
            print('Timeout!', file=summary)
        try:
            p.kill()
        except Exception:
            pass
        t.join()


class TestSuite:
    def __init__(self, gdb, plugin, host, assembly, logdir, timeout, regex, repeat):
        self.gdb = gdb
        self.plugin = plugin
        self.host = host
        self.assembly = assembly
        self.logdir = logdir
        self.timeout = timeout
        self.regex = regex
        self.repeat = repeat
        self.summary_file = os.path.join(logdir, 'summary')
        self.fail_flag = os.path.join(logdir, 'fail_flag')
        self.fail_flag_gdb = os.path.join(logdir, 'fail_flag.gdb')

    def do_test(self, scenario):
        global tests_failed
        # Create fail_flag; GDB removes it on success via gdbtestutils.run
        open(self.fail_flag, 'a').close()
        # Remove previous marker
        try:
            os.unlink(self.fail_flag_gdb)
        except Exception:
            pass

        logfile = os.path.join(self.logdir, scenario)

        # Build the gdb command line
        # Notes:
        # -q: quiet, -nx: no init files, -batch: exit after commands
        # -ex: commands; we disable pagination and confirmations for stability
        cmd = (
            f"{self.gdb} -q -nx -batch "
            f"-ex \"set confirm off\" "
            f"-ex \"set pagination off\" "
            f"-ex \"python open('{self.fail_flag_gdb}', 'a').close()\" "
            f"-ex \"python import sys; sys.path.insert(0, '{os.path.abspath(os.path.dirname(__file__))}')\" "
            f"-ex \"source {self.plugin}\" "
            f"-ex \"python import gdbtestutils as test\" "
            f"-ex \"python test.fail_flag = '{self.fail_flag}'\" "
            f"-ex \"python test.summary_file = '{self.summary_file}'\" "
            f"-ex \"python test.run('{self.host}', '{self.assembly}', 'scenarios.{scenario}')\" "
            f"-ex \"quit\" "
            f" > {logfile}.log 2>&1"
        )

        run_with_timeout(cmd, self.timeout, self.summary_file)

        # A successful test deletes fail_flag and creates fail_flag.gdb
        if os.path.isfile(self.fail_flag) or not os.path.isfile(self.fail_flag_gdb):
            tests_failed = True

        # Clean flags for next test
        for f in (self.fail_flag, self.fail_flag_gdb):
            try:
                os.unlink(f)
            except Exception:
                pass

    def run_all(self):
        # Initialize summary file
        try:
            os.unlink(self.summary_file)
        except Exception:
            pass

        # Discover scenarios in tests/gdb/scenarios as t_cmd_*.py
        scenarios_dir = os.path.join(os.path.dirname(__file__), 'scenarios')
        names = []
        for fn in os.listdir(scenarios_dir):
            if re.match(self.regex, fn):
                if fn.endswith('.py') and not fn.startswith('_'):
                    names.append(fn[:-3])
        names.sort()

        for _ in range(self.repeat):
            for n in names:
                # Write suite header to summary
                with open(self.summary_file, 'a+') as summary:
                    print(f"new_suite: {n}", file=summary)
                self.do_test(n)
                with open(self.summary_file, 'a+') as summary:
                    print('Completed!', file=summary)


def generate_report(summary_file):
    report = [{'name': 'TOTAL', True: 0, False: 0, 'completed': True}]
    fail_messages = []

    if not os.path.isfile(summary_file):
        print('No summary file to process!')
        return

    with open(summary_file, 'r') as summary:
        for line in summary:
            if line.startswith('new_suite: '):
                report.append({'name': line.split()[-1], True: 0, False: 0,
                               'completed': False, 'timeout': False})
            elif line.startswith('True'):
                report[-1][True] += 1
            elif line.startswith('False'):
                report[-1][False] += 1
            elif line.startswith('Completed!'):
                report[-1]['completed'] = True
            elif line.startswith('Timeout!'):
                report[-1]['timeout'] = True
            elif line.startswith('!!! '):
                fail_messages.append(line.rstrip('\n'))

    for suite in report[1:]:
        report[0][True] += suite[True]
        report[0][False] += suite[False]
        report[0]['completed'] &= suite['completed']

    for line in fail_messages:
        print(line)

    print()
    print('=' * 79)
    print('{:72} {:6}'.format('Test suite', 'Result'))
    print('-' * 79)
    for suite in report[1:]:
        if suite['timeout']:
            result = 'Timeout'
        elif suite[False]:
            result = 'Fail'
        elif not suite['completed']:
            result = 'Crash'
        elif suite[True]:
            result = 'Success'
        else:
            result = 'Please, report'
        print('{:68} {:>10}'.format(suite['name'], result))
    print('=' * 79)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--gdb', default='gdb')
    parser.add_argument('--plugin', default=os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src/diagnostics/artifacts/bin/current/sos.py')))
    parser.add_argument('--host', required=True)
    parser.add_argument('--assembly', required=True)
    parser.add_argument('--logdir', default=os.path.join(os.path.dirname(__file__), 'logs'))
    parser.add_argument('--timeout', default=120, type=int)
    parser.add_argument('--regex', default=r't_cmd_.*\\.py')
    parser.add_argument('--repeat', default=1, type=int)
    args = parser.parse_args()

    os.makedirs(args.logdir, exist_ok=True)

    suite = TestSuite(
        gdb=args.gdb,
        plugin=args.plugin,
        host=args.host,
        assembly=args.assembly,
        logdir=args.logdir,
        timeout=args.timeout,
        regex=args.regex,
        repeat=args.repeat,
    )

    suite.run_all()
    generate_report(suite.summary_file)

    if tests_failed:
        sys.exit(1)


if __name__ == '__main__':
    main()
