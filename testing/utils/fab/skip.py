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
from enum import Enum

# a list/set of resolutions
_RESULTS = [resolution.PASSED,
            resolution.FAILED,
            resolution.UNRESOLVED,
            resolution.UNTESTED,
            resolution.UNSUPPORTED]

def add_arguments(parser):
    group = parser.add_argument_group("Result arguments")
    group.add_argument("--skip", action="append",
                       default=list(), choices=_RESULTS,
                       help="skip test with previous result; default: '%(default)s'")
    group.add_argument("--result", action="append",
                       default=list(), choices=_RESULTS,
                       help="include test with previous result; default: '%(default)s'")

def log_arguments(logger, args):
    logger.info("Result arguments:")
    logger.info("  skip: %s", args.skip)
    logger.info("  result: %s", args.result)

def result(logger, args, result):
    if result.resolution in args.skip:
        return result.resolution
    if args.result and result.resolution not in args.result:
        return result.resolution
    return None
