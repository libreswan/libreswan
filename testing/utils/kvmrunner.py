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
import os
import re
import pexpect
import argparse
import shutil
import subprocess
import time
from datetime import datetime
from distutils import util
from concurrent import futures
from fab import runner
from fab import testsuite
from fab import logutil
from fab import post
from fab import stats

def main():
    parser = argparse.ArgumentParser(description="Run tests")

    # This argument's behaviour is overloaded; the shorter word "try"
    # is a python word.
    parser.add_argument("--retry", type=int, metavar="COUNT", default=1,
                        help="which previously run tests should be retried: 0 selects not-started tests; 1 selects not-started+failed tests; -1 selects not-started+failed+passed tests (default is %(default)s)")
    parser.add_argument("--attempts", type=bool, default=1,
                        help="number of times to attempt a test before giving up; default %(default)s")

    parser.add_argument("--dry-run", "-n", action="store_true")
    parser.add_argument("--verbose", "-v", action="count", default=0)

    # Default to BACKUP under the current directory.  Name is
    # arbitrary, chosen for its hopefully unique first letter
    # (avoiding Makefile, OBJ, README, ... :-).
    parser.add_argument("--backup-directory", metavar="DIRECTORY",
                        default=os.path.join("BACKUP", time.strftime("%Y%m%d%H%M%S", time.localtime())),
                        help="backup existing <test>/OUTPUT to %(metavar)s/<test> (default: %(default)s)")

    parser.add_argument("directories", metavar="DIRECTORY", nargs="+",
                        help="either a testsuite directory or a list of test directories")
    testsuite.add_arguments(parser)
    runner.add_arguments(parser)
    post.add_arguments(parser)
    logutil.add_arguments(parser)

    args = parser.parse_args()
    logutil.config(args)

    logger = logutil.getLogger("kvmrunner")
    logger.info("Options:")
    logger.info("  retry: %s", args.retry)
    logger.info("  attempts: %s", args.attempts)
    logger.info("  dry-run: %s", args.dry_run)
    logger.info("  backup-directory: %s", args.backup_directory)
    logger.info("  directories: %s", args.directories)
    testsuite.log_arguments(logger, args)
    runner.log_arguments(logger, args)
    post.log_arguments(logger, args)
    logutil.log_arguments(logger, args)

    tests = testsuite.load_testsuite_or_tests(logger, args.directories, args,
                                              log_level=logutil.INFO)
    if not tests:
        logger.error("test or testsuite directory invalid: %s", args.directories)
        return 1

    test_stats = stats.Tests()
    result_stats = stats.Results()

    # Save the previous test results.  Do it up-front so that the
    # saved results are always a complete copy of the original test
    # output.
    logger.info("copying existing results to %s ...", args.backup_directory)
    saved_tests = 0
    for test in tests:
        if os.path.exists(test.output_directory):
            backup_directory = os.path.join(args.backup_directory, test.name)
            level = logutil.DEBUG
            logger.debug("copying '%s' in '%s'",
                         test.output_directory, backup_directory)
            if not args.dry_run:
                saved_tests += 1
                os.makedirs(os.path.dirname(backup_directory), exist_ok=True)
                shutil.copytree(test.output_directory, backup_directory)
    logger.info("... %d test results saved", saved_tests)

    try:
        logger.info("run started at %s", datetime.now())

        test_count = 0
        for test in tests:
            test_stats.add("total", test)
            test_count += 1
            # Would the number of tests to be [re]run be better?
            test_prefix = "****** %s (test %d of %d)" % (test.name, test_count, len(tests))

            ignore = testsuite.ignore(test, args)
            if ignore:
                result_stats.add_ignore(test, ignore)
                test_stats.add("ignored", test)
                # No need to log all the ignored tests when an
                # explicit sub-set of tests is being run.  For
                # instance, when running just one test.
                if not args.test_name:
                    logger.info("%s: ignore (%s)", test_prefix, ignore)
                continue

            # Implement "--retry" as described above: if retry is -ve,
            # the test is always run; if there's no result, the test
            # is always run; skip passed tests; else things get a
            # little wierd.

            # Be lazy with gathering the results, don't run the
            # sanitizer or diff.
            old_result = post.mortem(test, args, skip_diff=True, skip_sanitize=True)
            if args.retry >= 0:
                if old_result:
                    if old_result.passed:
                        logger.info("%s: passed", test_prefix)
                        test_stats.add("skipped", test)
                        result_stats.add_skip(old_result)
                        continue
                    if args.retry == 0:
                        logger.info("%s: %s (delete '%s' to re-test)", test_prefix,
                                    result, test.output_directory)
                        test_stats.add("skipped", test)
                        result_stats.add_skip(old_result)
                        continue
                    test_stats.add("retry", test)

            logger.info("%s: starting ...", test_prefix)
            test_stats.add("tests", test)

            debugfile = None
            result = None

            # At least one iteration; above will have filtered out
            # skips and ignores
            for attempt in range(args.attempts):
                test_stats.add("attempts", test)

                # On first attempt (attempt == 0), empty the
                # <test>/OUTPUT/ directory of all contents.  On
                # subsequent attempts, move the files from the
                # previous attempt to <test>/OUTPUT/<attempt>/.
                #
                # XXX: Don't just delete the OUTPUT/ directory as
                # this, for a short period, changes the status of the
                # test to never-run.
                #
                # XXX: During boot, swan-transmogrify runs "chcon -R
                # testing/pluto".  Of course this means that each time
                # a test is added and/or a test is run (adding files
                # under <test>/OUTPUT), the boot process (and
                # consequently the time taken to run a test) keeps
                # increasing.
                #
                # Mitigate this slightly by emptying <test>/OUTPUT
                # before starting any test attempts.  It's assumed
                # that the previous test run was already captured
                # above with save-directory.

                if not args.dry_run:
                    try:
                        os.mkdir(test.output_directory)
                    except FileExistsError:
                        saved_output_directory = os.path.join(test.output_directory, str(attempt))
                        logger.info("emptying directory '%s'", test.output_directory)
                        for name in os.listdir(test.output_directory):
                            src = os.path.join(test.output_directory, name)
                            if attempt == 0:
                                logger.debug("  remove '%s'", src)
                                if os.path.isfile(src):
                                    os.remove(src)
                                else:
                                    shutil.rmtree(src)
                            elif os.path.isfile(src):
                                dst = os.path.join(saved_output_directory, name)
                                logger.debug("  move '%s' to '%s'", src, dst)
                                os.makedirs(saved_output_directory, exist_ok=True)
                                os.rename(src, dst)

                # Start a debug log in the OUTPUT directory; include
                # timing for this specific test attempt.
                with logutil.TIMER, logutil.Debug(logger, os.path.join(test.output_directory, "debug.log")):
                    logger.info("****** test %s attempt %d of %d started at %s ******",
                                test.name, attempt+1, args.attempts, datetime.now())

                    ending = "undefined"
                    try:
                        if not args.dry_run:
                            runner.run_test(test, max_workers=args.workers)
                        ending = "finished"
                        result = post.mortem(test, args, update=(not args.dry_run))
                        if not args.dry_run:
                            # Store enough to fool the script
                            # pluto-testlist-scan.sh.
                            logger.info("storing result in '%s'", test.result_file)
                            with open(test.result_file, "w") as f:
                                f.write('"result": "%s"\n' % result)
                    except pexpect.TIMEOUT as e:
                        ending = "timeout"
                        logger.exception("**** test %s timed out ****", test.name)
                        result = post.mortem(test, args, update=(not args.dry_run))
                    # Since the OUTPUT directory exists, all paths to
                    # here should have a non-null RESULT.
                    test_stats.add("attempts(%s:%s)" % (ending, result), test)
                    if result.errors:
                        logger.info("****** test %s %s %s ******", test.name, result, result.errors)
                    else:
                        logger.info("****** test %s %s ******", test.name, result)
                    if result.passed:
                        break

            # Above will have set RESULT (don't reach here during
            # cntrl-c or crash).

            test_stats.add("tests(%s)" % result, test)
            result_stats.add_result(result, old_result)

            logger.info("Results so far:")
            result_stats.log_summary(logger.info, prefix="  ")

    except KeyboardInterrupt:
        logger.exception("**** test %s interrupted ****", test.name)
        return 1

    finally:
        logger.info("run finished at %s", datetime.now())

        level = args.verbose and logger.info or logger.debug
        level("stat details:")
        test_stats.log_details(level, prefix="  ")

        logger.info("result details:")
        result_stats.log_details(logger.info, prefix="  ")

        logger.info("stat summary:")
        test_stats.log_summary(logger.info, prefix="  ")
        logger.info("result summary:")
        result_stats.log_summary(logger.info, prefix="  ")

    return 0


if __name__ == "__main__":
    sys.exit(main())
