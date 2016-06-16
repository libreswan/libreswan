# Test driver, for libreswan
#
# Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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

def add_arguments(parser):
    group = parser.add_argument_group("Skip arguments",
                                      "Arguments controlling which existing results to skip")
    group.add_argument("--skip-passed", action="store_true",
                       help="skip tests that passed during the previous test run")
    group.add_argument("--skip-failed", action="store_true",
                       help="skip tests that failed during the previous test run")
    group.add_argument("--skip-incomplete", action="store_true",
                       help="skip tests that did not complete during the previous test run")
    group.add_argument("--skip-untested", action="store_true",
                       help="skip tests that have not been previously run")

def log_arguments(logger, args):
    logger.info("Skip arguments:")
    logger.info("  skip-passed: %s", args.skip_passed)
    logger.info("  skip-failed: %s", args.skip_failed)
    logger.info("  skip-incomplete: %s", args.skip_incomplete)
    logger.info("  skip-untested: %s", args.skip_untested)

def result(logger, args, result):
    if args.skip_passed and result.finished and result.passed is True:
        return "passed"
    if args.skip_failed and result.finished and result.passed is False:
        return "failed"
    if args.skip_incomplete and result.finished is False:
        return "incomplete"
    if args.skip_untested and result.finished is None:
        return "untested"
    return None
