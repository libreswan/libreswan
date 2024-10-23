#!/usr/bin/env python3

# Print a test result summary gathered by scanning the OUTPUT.
#
# Copyright (C) 2015-2017 Andrew Cagney
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

import signal
import faulthandler
import argparse
import sys
import os
import re
from enum import Enum

from fab import testsuite
from fab import logutil
from fab import post
from fab import stats
from fab import skip
from fab import ignore
from fab import argutil
from fab import jsonutil
from fab import printer
from fab import publish
from fab import resolution


class Stats(Enum):
    def __str__(self):
        return self.value
    details = "details"
    summary = "summary"
    none = "none"


def main():

    # If SIGUSR1, backtrace all threads; hopefully this is early
    # enough.
    faulthandler.register(signal.SIGUSR1)

    parser = argparse.ArgumentParser(description="list test results",
                                     epilog="By default this tool uses 'sanitizer.sh' and 'diff' to generate up-to-the-minuite test results (the previously generated files 'OUTPUT/*.console.txt' and 'OUTPUT/*.console.diff' are ignored).  While this makes things a little slower, it has the benefit of always providing the most up-to-date and correct results (for instance, changes to known-good files are reflected immediately).  SIGUSR1 will dump all thread stacks")
    parser.add_argument("--verbose", "-v", action="count", default=0)

    parser.add_argument("--exit-ok", action="store_true",
                        help=("return a zero exit status; normally, when there are failures, a non-zero exit status is returned"))

    parser.add_argument("--quick", action="store_true",
                        help=("Use the previously generated '.console.txt' and '.console.diff' files"))

    parser.add_argument("--update", action="store_true",
                        help=("Update the '.console.txt' and '.console.diff' files"))

    parser.add_argument("--dump-args", action="store_true")

    # how to parse --print directory,saved-directory,...?
    parser.add_argument("--print", action="store",
                        default=printer.Print(printer.Print.PATH, printer.Print.RESULT, printer.Print.ISSUES),
                        type=printer.Print, metavar=str(printer.Print),
                        help="comma separated list of attributes to print for each test; default: '%(default)s'")

    parser.add_argument("--stats", action="store", default=Stats.summary, type=Stats,
                        choices=[c for c in Stats],
                        help="provide overview statistics; default: \"%(default)s\"");

    parser.add_argument("--json", action="store_true",
                        help="output each result as an individual json object (pipe the output through 'jq -s .' to convert it to a well formed json list")

    parser.add_argument("directories", metavar="DIRECTORY-OR-FILE", nargs="+",
                        help="a directory containing: a test, testsuite, test output, or testsuite output; or a file containing a 'TESTLIST'")

    testsuite.add_arguments(parser)
    logutil.add_arguments(parser)
    skip.add_arguments(parser)
    ignore.add_arguments(parser)
    publish.add_arguments(parser)

    # These three calls go together
    args = parser.parse_args()
    logutil.config(args, sys.stderr)
    logger = logutil.getLogger("kvmresults")

    if args.dump_args:
        logger.info("Arguments:")
        logger.info("  Stats: %s", args.stats)
        logger.info("  Print: %s", args.print)
        logger.info("  Json: %s", args.json)
        logger.info("  Quick: %s", args.quick)
        logger.info("  Update: %s", args.update)
        logger.info("  Exit OK: %s", args.exit_ok)
        testsuite.log_arguments(logger, args)
        logutil.log_arguments(logger, args)
        skip.log_arguments(logger, args)
        ignore.log_arguments(logger, args)
        publish.log_arguments(logger, args)
        return 0

    tests = testsuite.load_testsuite_or_tests(logger, args.directories, args)
    # And check
    if not tests:
        logger.error("Invalid testsuite or test directories")
        return 1

    result_stats = stats.Results()
    exit_code = 125 # assume a 'git bisect' barf
    try:
        exit_code = results(logger, tests, args, result_stats)
    finally:
        if args.stats is Stats.details:
            result_stats.log_details(stderr_log, header="Details:", prefix="  ")
        if args.stats in [Stats.details, Stats.summary]:
            result_stats.log_summary(stderr_log, header="Summary:", prefix="  ")

    return exit_code


def stderr_log(fmt, *args):
    sys.stderr.write(fmt % args)
    sys.stderr.write("\n")


def results(logger, tests, args, result_stats):

    failures = 0
    unresolved = 0
    passed = 0
    nr = 0

    for test in tests:

        nr = nr + 1
        publish.json_status(logger, args,
                            "rebuilding %s (test %d of %d)" % (test.name, nr, len(tests)))

        # If debug logging is enabled this will provide fine grained
        # per-test timing.

        with logger.debug_time("processing test %s", test.name):

            # Filter out tests that are being ignored?
            ignored, details = ignore.test(logger, args, test)
            if ignored:
                result_stats.add_ignored(test, ignored)
                continue

            # Filter out test results that are being skipped.
            #
            # XXX: In the default case (skip=[UNTESTED]) this should
            # be cheap (does OUTPUT/ exist?).  It isn't, instead a
            # full post-mortem analysis is performed.
            #
            # This is noticeable when printing static test value such
            # as the test's name takes far longer than one would
            # expect.
            result = post.mortem(test, args, logger,
                                 output_directory=test.saved_output_directory,
                                 quick=args.quick)
            if args.update:
                result.save()
            if args.skip or args.result:
                if printer.Print.RESULT in args.print \
                and skip.result(logger, args, result):
                    result_stats.add_skipped(result)
                    continue
            result_stats.add_result(result)

            if result.resolution in [resolution.PASSED,
                                     resolution.UNTESTED,
                                     resolution.UNSUPPORTED]:
                passed = passed + 1
            elif result.resolution in [resolution.UNRESOLVED]:
                unresolved = unresolved + 1
            else:
                failures = failures + 1

            publish.test_files(logger, args, result)
            publish.test_output_files(logger, args, result)
            publish.json_result(logger, args, result)

            b = args.json and printer.JsonBuilder(sys.stdout) or printer.TextBuilder(sys.stdout)
            printer.build_result(logger, result, args.print, b)

        publish.json_results(logger, args)
        publish.json_summary(logger, args)

    publish.json_status(logger, args, "finished")

    # exit code
    if args.exit_ok:
        return 0
    elif unresolved:
        return 125 # 'git bisect' magic for don't know
    elif failures:
        return 1
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())
