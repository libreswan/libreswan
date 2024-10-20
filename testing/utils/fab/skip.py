# Test driver, for libreswan
#
# Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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

from fab import argutil
from fab import resolution

# a list/set of resolutions
class Skip(argutil.List):
    PASSED = resolution.PASSED
    FAILED = resolution.FAILED
    UNRESOLVED = resolution.UNRESOLVED
    UNTESTED = resolution.UNTESTED
    UNSUPPORTED = resolution.UNSUPPORTED

def add_arguments(parser, *defaults):
    group = parser.add_argument_group("Skip arguments")
    group.add_argument("--skip", action="store",
                       default=Skip(*defaults),
                       type=Skip, metavar=str(Skip),
                       help="comma separated list of previous test results to skip; default: '%(default)s'")

def log_arguments(logger, args):
    logger.info("Skip arguments:")
    logger.info("  skip: %s", args.skip)

def result(logger, args, result):
    if result.resolution in args.skip:
        return result.resolution
    return None
