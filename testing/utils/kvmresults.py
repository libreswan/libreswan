#!/usr/bin/env python3

# Print a test result summary gathered by scanning the OUTPUT.
#
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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
from fab import testsuite
from fab import logutil
from fab import post

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

    parser.add_argument("--print-directory", action="store_true")
    parser.add_argument("--print-name", action="store_true")
    # parser.add_argument("--print-result", action="store_true")
    parser.add_argument("--print-diff", action="store_true")
    parser.add_argument("--print-args", action="store_true")
    parser.add_argument("--print-output-directory", action="store_true")

    parser.add_argument("--list-ignored", action="store_true",
                        help="include ignored tests in the list")
    parser.add_argument("--list-untested", action="store_true",
                        help="include untested tests in the list")

    parser.add_argument("directories", metavar="TEST-DIRECTORY", nargs="+",
                        help=("Either a testsuite (only one) or test directory"))
    # Note: this argument serves as documentation only.  The
    # TEST-DIRECTORY argument always consume all remaining parameters.
    parser.add_argument("baseline", metavar="BASELINE-DIRECTORY", nargs="?",
                        help=("An optional testsuite directory containing"
                              " results from a previous test run"))
    post.add_arguments(parser)
    testsuite.add_arguments(parser)
    logutil.add_arguments(parser)

    args = parser.parse_args()

    logutil.config(args)
    logger = logutil.getLogger("kvmresults")

    # The option -vvvvvvv is a short circuit for these; make
    # re-ordering easy by using V as a counter.
    v = 0
    args.print_directory = args.print_directory or args.verbose > v
    args.print_name = args.print_name or args.verbose > v
    v += 1
    args.print_output_directory = args.print_output_directory or args.verbose > v
    v += 1
    args.list_untested = args.list_untested or args.verbose > v ; v += 1
    args.list_ignored = args.list_ignored or args.verbose > v ; v += 1
    v += 1
    args.print_args = args.print_args or args.verbose > v

    if args.print_args:
        post.log_arguments(logger, args)
        testsuite.log_arguments(logger, args)
        logutil.log_arguments(logger, args)
        return 1

    # Is the last argument some sort of baseline?  If it is, pre-load
    # it.
    #
    # XXX: Should also support something like --baseline-testsuite and
    # --baseline-output parameters.
    baseline = None
    if len(args.directories) > 1:
        # If there is more than one directory then, perhaps, the last
        # one is a baseline.  A baseline might be: a complete
        # testsuite snapshot; or just output saved as
        # testing/pluto/OUTPUT/TESTDIR.
        baseline = testsuite.load(logger, args.directories[-1], args,
                                  error_level=logutil.DEBUG)
        if baseline:
            # discard the last argument as consumed above.
            logger.debug("discarding baseline testsuite argument '%s'", args.directories[-1])
            args.directories.pop()

    tests = testsuite.load_testsuite_or_tests(logger, args.directories, args)
    # And check
    if not tests:
        logger.error("Invalid testsuite or test directories")
        return 1

    # When an explicit list of directories was specified always print
    # all of them (otherwise, tests seem to get lost).
    if isinstance(tests, list):
        args.list_untested = True

    for test in tests:

        # Produce separate runtimes for each test.
        with logutil.TIMER:

            logger.debug("start processing test %s", test.name)

            # Filter out tests that are being ignored?
            ignore = testsuite.ignore(test, args)
            if ignore and not args.list_ignored:
                continue

            # Filter out tests that have not been run?
            result = None
            if not ignore:
                result = post.mortem(test, args, baseline=baseline,
                                     output_directory=test.saved_output_directory,
                                     skip_sanitize=args.quick or args.quick_sanitize,
                                     skip_diff=args.quick or args.quick_diff,
                                     update=args.update,
                                     update_sanitize=args.update_sanitize,
                                     update_diff=args.update_diff)
                if not result and not args.list_untested:
                    continue

            sep = ""

            # Print the test's name/path
            if not args.print_directory and not args.print_name and not args.print_output_directory:
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
                if args.print_name:
                    print(sep, end="")
                    print(test.name, end="")
                    sep = " "
                if args.print_directory:
                    print(sep, end="")
                    print(test.directory, end="")
                    sep = " "
                if args.print_output_directory:
                    print(sep, end="")
                    print((test.saved_output_directory
                           and test.saved_output_directory
                           or test.output_directory), end="")
                    sep = " "

            if ignore:
                print(sep, end="")
                print("ignored", ignore, end="")
                sep = " "

            print(sep, end="")
            if result.errors:
                print(result, result.errors, end="")
            else:
                print(result, end="")
            sep = " "

            print()

            if args.print_diff and result:
                for domain in result.diffs:
                    for line in result.diffs[domain]:
                        if line:
                            print(line)

            sys.stdout.flush()

            logger.debug("stop processing test %s", test.name)

    return 0


if __name__ == "__main__":
    sys.exit(main())
