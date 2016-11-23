# Lists the tests
#
# Copyright (C) 2015-2015, Andrew Cagney <cagney@gnu.org>
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

import re


def add_arguments(parser):
    group = parser.add_argument_group("Test filter arguments",
                                      "Options for selecting the tests to run or ignore")
    group.add_argument("--test-kind", default="kvmplutotest",
                       type=re.compile, metavar="REGULAR-EXPRESSION",
                       help="Select tests with kind matching %(metavar)s (default: '%(default)s')")
    group.add_argument("--test-result", default="good",
                       type=re.compile, metavar="REGULAR-EXPRESSION",
                       help="Select tests with (expected) result matching %(metavar)s (default: '%(default)s')")


def log_arguments(logger, args):
    logger.info("Test filter arguments:")
    logger.info("  test-kind: '%s'" , args.test_kind.pattern)
    logger.info("  test-result: '%s'" , args.test_result.pattern)


def test(logger, args, test):

    """Identify tests that should be ignored due to filters

    Returns the ignore reason (or None), really ignore (or False), and details.

    This is different to SKIP where a test isn't run because it has
    been run before.

    """

    if args.test_kind.pattern and not args.test_kind.search(test.kind):
        return test.kind, "kind '%s' does not match '%s'" % (test.kind, args.test_kind.pattern)
    if args.test_result.pattern and not args.test_result.search(test.status):
        return test.status, "expected test result '%s' does not match '%s'" % (test.status, args.test_result.pattern)

    return None, None
