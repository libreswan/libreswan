#!/usr/bin/env python3

# Print results "table.json" on standard output.
#
# Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

import argparse
import sys
import re
from datetime import datetime
from datetime import timedelta
from os import path

from fab import jsonutil
from fab import utilsdir

def main():

    parser = argparse.ArgumentParser(description="write 'table.json' to standard output")

    parser.add_argument("--rundir", action="store",
                        default=path.basename(utilsdir.realpath("..", "..")),
                        help="what to stuff into the 'runDir:' JSON field")
    parser.add_argument("--verbose", "-v", action="store_true")

    parser.add_argument("directories", metavar="OUTPUT-DIRECTORY", nargs="+",
                        help="output directories containing RESULT files")

    args = parser.parse_args()

    # Force the order
    host_names = [ "east", "west", "road", "north", "nic" ]
    columns = [ "Test", "Expected", "Result", "Run time" ]
    for host in host_names:
        columns.append(host)
    rows = []

    first_time = last_time = None
    total = passed = failed = incomplete = 0

    for directory in args.directories:

        d = directory

        if not path.isdir(d):
            sys.stderr.write("%s (%s) is not a directory\n" % (directory, d))
            return 1

        # work around python's basename - remove any trailing "/"
        if not path.basename(d):
            d = path.dirname(d)

        if path.basename(d) != "OUTPUT":
            # try <d>/OUTPUT
            t = path.join(d, "OUTPUT")
            if not path.isdir(t):
                sys.stderr.write("%s (%s) is not an OUTPUT directory\n" % (directory, d))
                return 1
            d = t

        result_file = path.join(d, "RESULT")
        debug_log = path.join(d, "debug.log")

        if not path.isfile(result_file) and not path.isfile(debug_log):
            sys.stderr.write("%s (%s) contains no results\n" % (directory, d))
            return 1

        testname = path.basename(path.dirname(d))
        args.verbose and sys.stderr.write("%s\n" % (testname))

        total += 1

        runtime = ""

        RESULT = {}
        if path.isfile(result_file):
            # The RESULT file contains lines of JSON.  The last is
            # the result, and within that is the runtime. field.
            last_line = None
            with open(result_file) as f:
                for line in f:
                    try:
                        j = jsonutil.loads(line)
                    except:
                        sys.stderr.write("%s: invalid json: <<%s>>\n" % (result_file, line))
                        break
                    if not j:
                        break
                    if "result" in j:
                        RESULT = j
                        break

        # The debug.log should contain start/end lines, even when
        # the test didn't finish properly.
        debug_start_time = ""
        debug_end_time = ""
        debug_runtime = ""
        if path.isfile(debug_log):
            with open(debug_log) as f:
                debug = f.read()
                debug_start_time = debug_time(r"starting debug log at (.*)$", debug)
                debug_end_time = debug_time(r"ending debug log at (.*)$", debug)
        if debug_start_time and debug_end_time:
            debug_runtime = round((debug_end_time - debug_start_time).total_seconds(), 2)

        # .../<testname>/OUTPUT
        if jsonutil.result.testname in RESULT:
            testname = RESULT[jsonutil.result.testname]

        result = "incomplete"
        if jsonutil.result.result in RESULT:
            result = RESULT[jsonutil.result.result]
        if result == "passed":
            passed += 1
        elif result == "failed":
            failed += 1
        else:
            incomplete += 1

        expect = "good"
        if jsonutil.result.expect in RESULT:
            expect = RESULT[jsonutil.result.expect]

        end_time = ""
        if debug_end_time:
            end_time = debug_end_time
        if not end_time and jsonutil.result.time in RESULT:
            end_time = jsonutil.ptime(RESULT[jsonutil.result.time])

        runtime = ""
        if debug_runtime:
            runtime = debug_runtime
        if not runtime and jsonutil.result.runtime in RESULT:
            runtime = RESULT[jsonutil.result.runtime]

        start_time = ""
        if debug_start_time:
            start_time = debug_start_time
        if not start_time and end_time and runtime:
            start_time = end_time - timedelta(seconds=runtime)

        if not first_time:
            first_time = start_time
        elif start_time < first_time:
            first_time = start_time

        if not last_time:
            last_time = end_time
        elif end_time > last_time:
            last_time = end_time

        row = [
            testname,
            expect,
            result,
            runtime,
        ]

        if jsonutil.result.host_results in RESULT:
            host_results = RESULT[jsonutil.result.host_results]
            for host in host_names:
                if host in host_results:
                    row.append(host_results[host])
                else:
                    row.append("")

        rows.append(row)

    runtime = "00:00:00"
    if first_time and last_time:
        runtime = (last_time - first_time)
        runtime = str(timedelta(days=runtime.days,seconds=runtime.seconds))

    date = "0000-00-00 00:00"
    if first_time:
        date = first_time.strftime("%Y-%m-%d %H:%M")

    summary = {
        jsonutil.summary.total: total,
        jsonutil.summary.passed: passed,
        jsonutil.summary.failed: failed,
        jsonutil.summary.incomplete: incomplete,
        jsonutil.summary.date: date,
        jsonutil.summary.runtime: runtime,
    }

    table = {
        jsonutil.table.rundir: args.rundir,
        jsonutil.table.suffix: "/OUTPUT",
        jsonutil.table.summary: summary,
        jsonutil.table.columns: columns,
        jsonutil.table.rows: rows,
    }
    jsonutil.dump(table, sys.stdout)
    sys.stdout.write("\n")

    return 0


def debug_time(regex, debug):
    time = re.search(regex, debug, re.MULTILINE)
    if not time:
        return ""
    time = time.group(1)
    if not time:
        return ""
    return datetime.strptime(time, "%Y-%m-%d %H:%M:%S.%f")


if __name__ == "__main__":
    sys.exit(main())
