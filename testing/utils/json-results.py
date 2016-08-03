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
    total = passed = failed = incomplete = good = 0

    for directory in args.directories:

        args.verbose and sys.stderr.write("%s\n" % (directory))

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
            continue

        total += 1

        runtime = ""

        RESULT = {}

        # If the RESULT file exists, use that.
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

        # fill in anyting that is missing

        # Relative path to this directory so that html can construct
        # link.
        RESULT[jsonutil.result.directory] = d

        # Testname from .../<testname>/OUTPUT.
        if not jsonutil.result.testname in RESULT:
            # Python dirname is really basename(dirname).
            RESULT[jsonutil.result.testname] = path.dirname(d)

        if not jsonutil.result.result in RESULT:
            RESULT[jsonutil.result.result] = "incomplete"
        if RESULT[jsonutil.result.result] == "passed":
            passed += 1
        elif RESULT[jsonutil.result.result] == "failed":
            failed += 1
        else:
            incomplete += 1

        if not jsonutil.result.expect in RESULT:
            RESULT[jsonutil.result.expect] = "good"
        if RESULT[jsonutil.result.expect] == "good":
            good += 1

        # this is the end-time
        if not jsonutil.result.time in RESULT and debug_end_time:
            RESULT[jsonutil.result.time] = jsonutil.ftime(debug_end_time)
        # having separate boottime and testtime would be nice
        if not jsonutil.result.runtime in RESULT and debug_runtime:
            RESULT[jsonutil.result.runtime] = debug_runtime

        # Update the total times

        end_time = ""
        if debug_end_time:
            end_time = debug_end_time
        elif jsonutil.result.time in RESULT:
            end_time = jsonutil.ptime(RESULT[jsonutil.result.time])

        start_time = ""
        if debug_start_time:
            start_time = debug_start_time
        elif end_time and runtime:
            start_time = end_time - timedelta(seconds=runtime)

        if start_time:
            if not first_time:
                first_time = start_time
            elif start_time < first_time:
                first_time = start_time

        if end_time:
            if not last_time:
                last_time = end_time
            elif end_time > last_time:
                last_time = end_time

        rows.append(RESULT)

    runtime = "00:00:00"
    if first_time and last_time:
        runtime = (last_time - first_time)
        runtime = str(timedelta(days=runtime.days,seconds=runtime.seconds))

    date = jsonutil.ftime(datetime.fromordinal(1))
    if first_time:
        date = jsonutil.ftime(first_time)

    summary = {
        jsonutil.summary.total: total,
        jsonutil.summary.passed: passed,
        jsonutil.summary.failed: failed,
        jsonutil.summary.incomplete: incomplete,
        jsonutil.summary.date: date,
        jsonutil.summary.runtime: runtime,
        jsonutil.summary.good: good,
    }

    table = {
        jsonutil.results.summary: summary,
        jsonutil.results.table: rows,
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
