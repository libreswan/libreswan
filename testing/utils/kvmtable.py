#!/usr/bin/env python3

# Print "table.json" on standard output.
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
import os
import json
from enum import Enum

from fab import testsuite
from fab import logutil
from fab import post
from fab import stats
from fab import skip
from fab import ignore


def main():

    parser = argparse.ArgumentParser(description="write 'table.json' to standard output")
    parser.add_argument("--verbose", "-v", action="count", default=0)

    parser.add_argument("--quick", action="store_true",
                        help=("Use the previously generated '.console.txt' and '.console.diff' files"))
    parser.add_argument("--quick-sanitize", action="store_true",
                        help=("Use the previously generated '.console.txt' file"))
    parser.add_argument("--quick-diff", action="store_true",
                        help=("Use the previously generated '.console.diff' file"))

    parser.add_argument("--update", action="store_true",
                        help=("Update the '.console.txt' and '.console.diff' files"))
    parser.add_argument("--update-sanitize", action="store_true",
                        help=("Update the '.console.txt' file"))
    parser.add_argument("--update-diff", action="store_true",
                        help=("Update the '.console.diff' file"))

    parser.add_argument("directories", metavar="DIRECTORY", nargs="+",
                        help="%(metavar)s containing: a test, a testsuite (contains a TESTLIST file), a TESTLIST file, test output, or testsuite output")

    post.add_arguments(parser)
    testsuite.add_arguments(parser)
    logutil.add_arguments(parser)
    skip.add_arguments(parser)
    ignore.add_arguments(parser)

    args = parser.parse_args()

    logutil.config(args)
    logger = logutil.getLogger("kvmresults")

    tests = testsuite.load_testsuite_or_tests(logger, args.directories, args)
    # And check
    if not tests:
        logger.error("Invalid testsuite or test directories")
        return 1

    columns = [ "Test", "Expected", "Result", "Run time", "Responder", "..." ]
    rows = []

    for test in tests:

        sys.stderr.write("%s\n" % test.name)

        # Filter out tests that are being ignored?
        ignored, include_ignored, details = ignore.test(logger, args, test)
        if ignored:
            if not include_ignored:
                continue

        # Filter out tests that have not been run
        result = None
        if not ignored:
            result = post.mortem(test, args, baseline=None,
                                 output_directory=test.saved_output_directory,
                                 test_finished=None,
                                 skip_sanitize=args.quick or args.quick_sanitize,
                                 skip_diff=args.quick or args.quick_diff,
                                 update=args.update,
                                 update_sanitize=args.update_sanitize,
                                 update_diff=args.update_diff)
            if skip.result(logger, args, result):
                continue

        row = [
            test.name,
            test.expected_result, str(result),
            "run-time"
        ]
        for host in sorted(test.host_names):
            errors = result.errors.errors
            if host in errors:
                row.append("%s %s" % (host, " ".join(sorted(errors[host]))))
            else:
                row.append("%s passed" % (host))

        rows.append(row)

    summary = {
        "Total": 0,
        "passed": 0,
        "failed": 0,
        "abort": 0,
        "missing baseline": 0,
        "missing console output": 0,
        "missing OUTPUT": 0,
        "missing RESULT": 0,
        "ASSERT": 0,
        "CORE": 0,
        "EXPECT": 0,
        "GPFAULT": 0,
        "SEGFAULT": 0,
        "date": "0000-00-00",
        "dir": "testing/pluto",
        "runtime": 0,
        "runtime_str": "00:00:00",
    }

    table = {
        "suffix": "/OUTPUT",
        "summary": summary,
        "columns": columns,
        "rows": rows,
        "runDir": "???",
    }
    print(json.dumps(table, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
