#!/usr/bin/env python3

# Print a test result summary gathered by scanning the OUTPUT.
#
# Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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
from enum import Enum

from fab import testsuite
from fab import logutil
from fab import post
from fab import stats
from fab import skip
from fab import ignore


class Print(Enum):
    def __str__(self):
        return self.value
    diffs = "diffs"
    directory = "directory"
    expected_result = "expected-result"
    full_name = "full-name"
    host_names = "host-names"
    kind = "kind"
    name = "name"
    output_directory = "output-directory"
    result = "result"
    sanitize_directory = "sanitize-directory"
    saved_output_directory = "saved-output-directory"
    scripts = "scripts"


class Prefix(Enum):
    def __str__(self):
        return self.value
    name = "name"
    test_directory = "test-directory"
    output_directory = "output-directory"


class Stats(Enum):
    def __str__(self):
        return self.value
    details = "details"
    summary = "summary"
    none = "none"


def main():

    parser = argparse.ArgumentParser(description="list all tests in the form: <test> [ <directory> ] [ <result> <details...> ]",
                                     epilog="By default this tool uses 'sanitizer.sh' and 'diff' to generate up-to-the-minuite test results (the previously generated files 'OUTPUT/*.console.txt' and 'OUTPUT/*.console.diff' are ignored).  While this makes things a little slower, it has the benefit of always providing the most up-to-date and correct results (for instance, changes to known-good files are reflected immediately).  If a BASELINE directory is specified, anywhere a test result is different to the baseline is also identified.")
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

    parser.add_argument("--dump-args", action="store_true")

    parser.add_argument("--prefix", action="store", type=Prefix,
                        choices=[p for p in Prefix],
                        help="prefix to display with each test")

    # how to parse --print directory,saved-directory,...?
    parser.add_argument("--print", action="append", default=[],
                        choices=[p for p in Print], type=Print,
                        help="what information to display about each test")

    parser.add_argument("--stats", action="store", default=Stats.summary, type=Stats,
                        choices=[c for c in Stats],
                        help="provide overview statistics; default: \"%(default)s\"");

    parser.add_argument("--baseline", metavar="DIRECTORY",
                        help="a %(metavar)s containing baseline testsuite output")

    parser.add_argument("directories", metavar="DIRECTORY", nargs="+",
                        help="%(metavar)s containing: a test, a testsuite (contains a TESTLIST file), a TESTLIST file, test output, or testsuite output")
    # Note: this argument serves as documentation only.  The
    # TEST-DIRECTORY argument always consumes all remaining arguments.
    parser.add_argument("baseline", metavar="BASELINE-DIRECTORY", nargs="?",
                        help="an optional testsuite directory (contains a TESTLIST file) containing output from a previous test run")

    post.add_arguments(parser)
    testsuite.add_arguments(parser)
    logutil.add_arguments(parser)
    skip.add_arguments(parser)
    ignore.add_arguments(parser)

    args = parser.parse_args()

    logutil.config(args)
    logger = logutil.getLogger("kvmresults")

    # default to printing results
    if not args.print:
        args.print = [Print.result]

    # The option -vvvvvvv is a short circuit for these; make
    # re-ordering easy by using V as a counter.
    v = 0

    if args.dump_args:
        logger.info("Arguments:")
        logger.info("  Stats: %s", args.stats)
        logger.info("  Print: %s", args.print)
        logger.info("  Prefix: %s", args.prefix)
        post.log_arguments(logger, args)
        testsuite.log_arguments(logger, args)
        logutil.log_arguments(logger, args)
        skip.log_arguments(logger, args)
        ignore.log_arguments(logger, args)
        return 0

    # Try to find a baseline.  If present, pre-load it.
    baseline = None
    if args.baseline:
        # An explict baseline testsuite, can be more forgiving in how
        # it is loaded.
        baseline = testsuite.load(logger, args,
                                  testsuite_directory=args.baseline,
                                  error_level=logutil.DEBUG)
        if not baseline:
            # Perhaps the baseline just contains output, magic up the
            # corresponding testsuite directory.
            baseline_directory = os.path.join(args.testing_directory, "pluto")
            baseline = testsuite.load(logger, args,
                                      testsuite_directory=baseline_directory,
                                      saved_testsuite_output_directory=args.baseline,
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

    return 0


def stderr_log(fmt, *args):
    sys.stderr.write(fmt % args)
    sys.stderr.write("\n")


def results(logger, tests, baseline, args, result_stats):

    for test in tests:

        # If debug logging is enabled this will provide per-test
        # timing.
        with logger.timer_stack():

            logger.debug("start processing test %s", test.name)

            # Filter out tests that are being ignored?
            ignored, include_ignored, details = ignore.test(logger, args, test)
            if ignored:
                result_stats.add_ignored(test, ignored)
                if not include_ignored:
                    continue

            # Filter out tests that have not been run
            result = None
            if not ignored and Print.result in args.print:
                result = post.mortem(test, args, baseline=baseline,
                                     output_directory=test.saved_output_directory,
                                     test_finished=None,
                                     skip_sanitize=args.quick or args.quick_sanitize,
                                     skip_diff=args.quick or args.quick_diff,
                                     update=args.update,
                                     update_sanitize=args.update_sanitize,
                                     update_diff=args.update_diff)
                if skip.result(logger, args, result):
                    continue

                if not result:
                    result_stats.add_ignored(test, str(result))
                else:
                    result_stats.add_result(result)

            sep = ""

            # Print the test's name/path
            if not args.prefix:
                # By default: when the path given on the command line
                # explicitly specifies a test's output directory
                # (found in TEST.SAVED_OUTPUT_DIRECTORY), print that;
                # otherwise print the path to the test's directory.
                print(sep, end="")
                print((test.saved_output_directory
                       and test.saved_output_directory
                       or test.directory), end="")
                sep = " "
            else:
                # Print the test name/path per command line
                if args.prefix is Prefix.name:
                    print(sep, end="")
                    print(test.name, end="")
                    sep = " "
                elif args.prefix is Prefix.test_directory:
                    print(sep, end="")
                    print(test.directory, end="")
                    sep = " "
                elif args.prefix is Prefix.output_directory:
                    print(sep, end="")
                    print((test.saved_output_directory
                           and test.saved_output_directory
                           or test.output_directory), end="")
                    sep = " "

            if ignored:
                print(sep, end="")
                print("ignored", ignored, end="")
                sep = " "

            for p in args.print:
                if p in [Print.diffs]:
                    continue
                elif p is Print.directory:
                    print(sep, end="")
                    print(test.directory, end="")
                    sep = " "
                elif p is Print.expected_result:
                    print(sep, end="")
                    print(test.expected_result, end="")
                    sep = " "
                elif p is Print.full_name:
                    print(sep, end="")
                    print(test.full_name, end="")
                    sep = " "
                elif p is Print.host_names:
                    for name in test.host_names:
                        print(sep, end="")
                        print(name, end="")
                        sep = ","
                    sep = " "
                elif p is Print.kind:
                    print(sep, end="")
                    print(test.kind, end="")
                    sep = " "
                elif p is Print.name:
                    print(sep, end="")
                    print(test.name, end="")
                    sep = " "
                elif p is Print.output_directory:
                    print(sep, end="")
                    print(test.output_directory, end="")
                    sep = " "
                elif p is Print.result:
                    if result:
                        print(sep, end="")
                        if result.errors:
                            print(result, result.errors, end="")
                        else:
                            print(result, end="")
                        sep = " "
                elif p is Print.sanitize_directory:
                    print(sep, end="")
                    print(test.sanitize_directory, end="")
                    sep = " "
                elif p is Print.saved_output_directory:
                    print(sep, end="")
                    print(test.saved_output_directory, end="")
                    sep = " "
                elif p is Print.scripts:
                    for host, script in test.host_script_tuples:
                        print(sep, end="")
                        print("%s:%s" % (host, script), end="")
                        sep = ","
                    sep = " "
                else:
                    print()
                    print("unknown print option", p)

            print()

            if Print.diffs in args.print and result:
                for domain in result.diffs:
                    for line in result.diffs[domain]:
                        if line:
                            print(line)

            sys.stdout.flush()

            logger.debug("stop processing test %s", test.name)


if __name__ == "__main__":
    sys.exit(main())
