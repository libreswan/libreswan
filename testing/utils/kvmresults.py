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


class Stats(Enum):
    def __str__(self):
        return self.value
    details = "details"
    summary = "summary"
    none = "none"


def main():

    parser = argparse.ArgumentParser(description="list test results",
                                     epilog="By default this tool uses 'sanitizer.sh' and 'diff' to generate up-to-the-minuite test results (the previously generated files 'OUTPUT/*.console.txt' and 'OUTPUT/*.console.diff' are ignored).  While this makes things a little slower, it has the benefit of always providing the most up-to-date and correct results (for instance, changes to known-good files are reflected immediately).")
    parser.add_argument("--verbose", "-v", action="count", default=0)

    parser.add_argument("--quick", action="store_true",
                        help=("Use the previously generated '.console.txt' and '.console.diff' files"))

    parser.add_argument("--update", action="store_true",
                        help=("Update the '.console.txt' and '.console.diff' files"))

    parser.add_argument("--dump-args", action="store_true")

    # how to parse --print directory,saved-directory,...?
    parser.add_argument("--print", action="store",
                        default=printer.Print(printer.Print.path, printer.Print.result, printer.Print.issues),
                        type=printer.Print, metavar=str(printer.Print),
                        help="comman separate list of attributes to print for each test; default: '%(default)s'")

    parser.add_argument("--stats", action="store", default=Stats.summary, type=Stats,
                        choices=[c for c in Stats],
                        help="provide overview statistics; default: \"%(default)s\"");

    baseline_metavar = "BASELINE-DIRECTORY"
    baseline_help = "additional %(metavar)s containing results to compare against; any divergence between the test and baseline results are displayed"
    parser.add_argument("--baseline", "-b",
                        metavar=baseline_metavar, help=baseline_help)

    parser.add_argument("--json", action="store_true",
                        help="output each result as an individual json object (pipe the output through 'jq -s .' to convert it to a well formed json list")

    parser.add_argument("directories", metavar="DIRECTORY-OR-FILE", nargs="+",
                        help="a directory containing: a test, testsuite, test output, or testsuite output; or a file containing a 'TESTLIST'")

    # Note: this argument serves as documentation only.  The RESULT
    # argument should consumes all remaining parameters.
    parser.add_argument("baseline_ignored", nargs="?",
                        metavar=baseline_metavar, help=baseline_help)

    testsuite.add_arguments(parser)
    logutil.add_arguments(parser)
    # XXX: while checking for an UNTESTED test should be very cheap
    # (does OUTPUT/ exist?) it isn't.  Currently it triggers a full
    # post-mortem analysis.
    skip.add_arguments(parser, skip.skip.untested)
    ignore.add_arguments(parser)
    publish.add_arguments(parser)

    # These three calls go together
    args = parser.parse_args()
    logutil.config(args, sys.stderr)
    logger = logutil.getLogger("kvmresults")

    # The option -vvvvvvv is a short circuit for these; make
    # re-ordering easy by using V as a counter.
    v = 0

    if args.dump_args:
        logger.info("Arguments:")
        logger.info("  Stats: %s", args.stats)
        logger.info("  Print: %s", args.print)
        logger.info("  Baseline: %s", args.baseline)
        logger.info("  Json: %s", args.json)
        logger.info("  Quick: %s", args.quick)
        logger.info("  Update: %s", args.update)
        testsuite.log_arguments(logger, args)
        logutil.log_arguments(logger, args)
        skip.log_arguments(logger, args)
        ignore.log_arguments(logger, args)
        publish.log_arguments(logger, args)
        return 0

    # Try to find a baseline.  If present, pre-load it.
    baseline = None
    if args.baseline:
        # An explict baseline testsuite, can be more forgiving in how
        # it is loaded.
        baseline = testsuite.load(logger, logutil.DEBUG, args,
                                  testsuite_directory=args.baseline,
                                  error_level=logutil.DEBUG)
        if not baseline:
            # Perhaps the baseline just contains output, magic up the
            # corresponding testsuite directory.
            baseline_directory = os.path.join(args.testing_directory, "pluto")
            baseline = testsuite.load(logger, logutil.DEBUG, args,
                                      testsuite_directory=baseline_directory,
                                      testsuite_output_directory=args.baseline,
                                      error_level=logutil.DEBUG)
        if not baseline:
            logger.info("'%s' is not a baseline", args.baseline)
            return 1
    elif len(args.directories) > 1:
        # If there is more than one directory then, perhaps, the last
        # one is a baseline.  A baseline might be: a complete
        # testsuite snapshot; or just output saved as
        # testing/pluto/OUTPUT/TESTDIR.
        baseline = testsuite.load(logger, logutil.DEBUG, args,
                                  testsuite_directory=args.directories[-1])
        if baseline:
            # discard the last argument as consumed above.
            logger.debug("discarding baseline testsuite argument '%s'", args.directories[-1])
            args.directories.pop()

    tests = testsuite.load_testsuite_or_tests(logger, args.directories, args)
    # And check
    if not tests:
        logger.error("Invalid testsuite or test directories")
        return 1

    result_stats = stats.Results()
    try:
        results(logger, tests, baseline, args, result_stats)
    finally:
        if args.stats is Stats.details:
            result_stats.log_details(stderr_log, header="Details:", prefix="  ")
        if args.stats in [Stats.details, Stats.summary]:
            result_stats.log_summary(stderr_log, header="Summary:", prefix="  ")
        publish.json_results(logger, args)
        publish.json_summary(logger, args)

    return 0


def stderr_log(fmt, *args):
    sys.stderr.write(fmt % args)
    sys.stderr.write("\n")


def results(logger, tests, baseline, args, result_stats):

    for test in tests:

        publish.json_status(logger, args, "rebuilding %s" % test.name)

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
            result = post.mortem(test, args,
                                 baseline=baseline,
                                 output_directory=test.saved_output_directory,
                                 quick=args.quick)
            if args.update:
                result.save()
            if args.skip:
                if skip.result(logger, args, result):
                    result_stats.add_skipped(result)
                    continue
            result_stats.add_result(result)

            publish.test_files(logger, args, result)
            publish.test_output_files(logger, args, result)
            publish.json_result(logger, args, result)

            if baseline and post.Issues.CRASHED.isdisjoint(result.issues):
                # Since there is a baseline and the test didn't crash
                # limit what is printed to just those where the
                # baseline's result is different.
                #
                # Note that, this skips baseline-different - where the
                # baseline failed for a different reason.
                if {post.Issues.BASELINE_FAILED, post.Issues.BASELINE_PASSED}.isdisjoint(result.issues):
                    continue

            b = args.json and printer.JsonBuilder(sys.stdout) or printer.TextBuilder(sys.stdout)
            printer.build_result(logger, result, baseline, args, args.print, b)

    publish.json_status(logger, args, "finished")

if __name__ == "__main__":
    sys.exit(main())
