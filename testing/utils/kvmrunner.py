#!/usr/bin/env python3

# Run the pluto testsuite, for libreswan
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

import sys
import argparse
from datetime import datetime

from fab import runner
from fab import testsuite
from fab import logutil
from fab import post
from fab import stats
from fab import skip
from fab import ignore
from fab import timing

def main():
    parser = argparse.ArgumentParser(description="Run tests")

    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument("--dry-run", "-n", action="store_true")

    parser.add_argument("directories", metavar="DIRECTORY", nargs="+",
                        help="a testsuite directory, a TESTLIST file, or a list of test directories")
    testsuite.add_arguments(parser)
    runner.add_arguments(parser)
    post.add_arguments(parser)
    logutil.add_arguments(parser)
    skip.add_arguments(parser)
    ignore.add_arguments(parser)

    args = parser.parse_args()
    logutil.config(args)

    logger = logutil.getLogger("kvmrunner")
    logger.info("Options:")
    logger.info("  directories: %s", args.directories)
    logger.info("  verbose: %s", args.verbose)
    logger.info("  dry-run: %s", args.dry_run)
    testsuite.log_arguments(logger, args)
    runner.log_arguments(logger, args)
    post.log_arguments(logger, args)
    logutil.log_arguments(logger, args)
    skip.log_arguments(logger, args)
    ignore.log_arguments(logger, args)

    tests = testsuite.load_testsuite_or_tests(logger, args.directories, args,
                                              log_level=logutil.INFO)
    if not tests:
        logger.error("test or testsuite directory invalid: %s", args.directories)
        return 1

    test_stats = stats.Tests()
    result_stats = stats.Results()

    try:
        exit_code = 0
        logger.info("run started at %s", timing.START_TIME)
        runner.run_tests(logger, args, tests, test_stats, result_stats)
    except KeyboardInterrupt:
        logger.exception("**** interrupted ****")
        exit_code = 1

    test_stats.log_details(args.verbose and logger.info or logger.debug,
                           header="final stat details:", prefix="  ")
    result_stats.log_details(logger.info, header="final test details:", prefix="  ")

    test_stats.log_summary(logger.info, header="final test stats:", prefix="  ")
    result_stats.log_summary(logger.info, header="final test results:", prefix="  ")

    end_time = datetime.now()
    logger.info("run finished at %s after %s", end_time, end_time - timing.START_TIME)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
