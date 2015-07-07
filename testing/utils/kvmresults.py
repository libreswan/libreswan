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

def main():

    parser = argparse.ArgumentParser(description="list all tests in the form: <test> [ <directory> ] [ <result> <details...> ]")
    parser.add_argument("--verbose", "-v", action="count", default=0)

    parser.add_argument("--print-result", action="store_true")
    parser.add_argument("--print-directory", action="store_true")

    parser.add_argument("--list-ignored", action="store_true",
                        help="include ignored tests in the list")
    parser.add_argument("--list-untested", action="store_true",
                        help="include untested tests in the list")

    parser.add_argument("directories", metavar="DIRECTORY", nargs="*",
                        help=("Either a testsuite directory or"
                              " a list of test directories; optionally followed"
                              " by a baseline testuite directory"))
    testsuite.add_arguments(parser)
    logutil.add_arguments(parser)

    args = parser.parse_args()

    logutil.config(args)
    logger = logutil.getLogger("kvmresults")

    # The option -vvvvvvv is a short circuit for these; make
    # re-ordering easy by using V as a counter.
    v = 0
    args.print_directory = args.print_directory or args.verbose > v ; v += 1
    args.list_untested = args.list_untested or args.verbose > v ; v += 1
    args.list_ignored = args.list_ignored or args.verbose > v ; v += 1

    # Decode all the arguments using a flawed heuristic.
    basetests = None
    tests = None
    if len(args.directories) > 1:
        # Perhaps the last argument is the baseline?
        basetests = testsuite.load(logger, args.directories[-1])
        if basetests:
            logger.debug("basetests loaded from '%s'", basetests.directory)
            args.directories.pop()
    tests = testsuite.load_testsuite_or_tests(logger, args.directories)
    logger.debug("basetests=%s", basetests)
    logger.debug("tests=%s", tests)
    # And check
    if not tests:
        logger.error("Invalid testsuite or test directories")
        return 1

    # Preload the baseline.  This avoids re-scanning the TESTLIST and,
    # when errors, printing those repeatedly.  Also, passing the full
    # baseline to Test.results() lets that function differentiate
    # between a baseline missing results or being entirely absent.
    baseline = None
    if basetests:
        baseline = {}
        for test in basetests:
            baseline[test.name] = test

    for test in tests:

        # Filter out tests that are being ignored?
        ignore = testsuite.ignore(test, args)
        if ignore and not args.list_ignored:
            continue

        # Filter out tests that have not been run?
        result = None
        if not ignore:
            result = test.result(baseline)
            if not result and not args.list_untested:
                continue

        print(test.name, end="")

        if args.print_directory:
            print("", test.directory, end="")

        if ignore:
            print("", "ignored", ignore, end="")
        elif result:
            print("", result, end="")

        print()

        sys.stdout.flush()

    return 0


if __name__ == "__main__":
    sys.exit(main())
