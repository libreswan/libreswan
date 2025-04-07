#!/usr/bin/env python3

# Run the pluto testsuite, for libreswan
#
# Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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
import sys
import argparse
import os
from datetime import datetime

from fab import runner
from fab import testsuite
from fab import logutil
from fab import post
from fab import stats
from fab import skip
from fab import ignore
from fab import timing
from fab import publish
from fab import argutil


def main():

    # If SIGUSR1, backtrace all threads; hopefully this is early
    # enough.
    faulthandler.register(signal.SIGUSR1)

    parser = argparse.ArgumentParser(description="Run tests",
                                     epilog="SIGUSR1 will dump all thread stacks")

    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument("--pid-file", default="", help="file to store process id of KVMRUNNER");

    parser.add_argument("directories", metavar="DIRECTORY", nargs="+",
                        help="a testsuite directory, a TESTLIST file, or a list of test directories")
    testsuite.add_arguments(parser)
    runner.add_arguments(parser)
    logutil.add_arguments(parser)
    skip.add_arguments(parser)
    ignore.add_arguments(parser)
    publish.add_arguments(parser)

    # These three calls go together
    args = parser.parse_args()
    logutil.config(args, sys.stdout)
    logger = logutil.getLogger("kvmrunner")

    argutil.log_args(logger, args)
    publish.process_arguments(logger, args)

    if args.pid_file:
        pid = os.getpid()
        logger.info("writing pid %d to '%s'", pid, args.pid_file)
        with open(args.pid_file, "wt") as pidfile:
            pidfile.write("%d\n" % os.getpid())

    tests = testsuite.load_testsuite_or_tests(logger, args.directories, args,
                                              log_level=logutil.INFO)
    if not tests:
        logger.error("test or testsuite directory invalid: %s", args.directories)
        return 1

    if len(tests) == 1 and args.run_post_mortem is None:
        logger.warning("skipping post-mortem.sh as only one test; use --run-post-mortem true to override this")
        args.run_post_mortem = False

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

    stop_time = datetime.now()
    logger.info("run finished at %s after %s", stop_time, stop_time - timing.START_TIME)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
