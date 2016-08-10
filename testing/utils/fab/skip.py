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

from fab import argutil

class skip(argutil.List):
    passed = "passed"
    failed = "failed"
    incomplete = "incomplete"
    untested = "untested"

def add_arguments(parser):
    group = parser.add_argument_group("Skip arguments")
    group.add_argument("--skip", action="store",
                       default=skip(),
                       type=skip, metavar=str(skip),
                       help="comma separated list of previous test results to skip; default: '%(default)s'")

def log_arguments(logger, args):
    logger.info("Skip arguments:")
    logger.info("  skip: %s", args.skip)

def result(logger, args, result):
    if skip.passed in args.skip and result.finished and result.passed is True:
        return "passed"
    if skip.failed in args.skip and result.finished and result.passed is False:
        return "failed"
    if skip.incomplete in args.skip and result.finished is False:
        return "incomplete"
    if skip.untested in args.skip and result.finished is None:
        return "untested"
    return None
