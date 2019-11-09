# Lists the tests
#
# Copyright (C) 2015-2016, Andrew Cagney <cagney@gnu.org>
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

import re
import argparse

def add_arguments(parser):
    group = parser.add_argument_group("Test filter arguments",
                                      "Options for selecting the tests to run or ignore")
    group.add_argument("--test-kind", default="kvmplutotest",
                       type=re.compile, metavar="REGULAR-EXPRESSION",
                       help="Select tests with kind matching %(metavar)s (default: '%(default)s')")
    group.add_argument("--test-status", default="good",
                       type=re.compile, metavar="REGULAR-EXPRESSION",
                       help="Select tests with status matching %(metavar)s (default: '%(default)s')")
    group.add_argument("--test-name", default="",
                       type=re.compile, metavar="REGULAR-EXPRESSION",
                       help="Select tests with name matching %(metavar)s (default: '%(default)s')")


def log_arguments(logger, args):
    logger.info("Test filter arguments:")
    logger.info("  test-kind: '%s'" , args.test_kind.pattern)
    logger.info("  test-status: '%s'" , args.test_status.pattern)
    logger.info("  test-name: '%s'" , args.test_name.pattern)


def test(logger, args, test):

    """Identify tests that should be ignored due to filters

    Returns the ignore reason (or None), really ignore (or False), and details.

    This is different to SKIP where a test isn't run because it has
    been run before.

    """

    for arg, field, title in [(args.test_kind, test.kind, "kind"),
                              (args.test_status, test.status, "status"),
                              (args.test_name, test.name, "name")]:
        if not arg.pattern:
            continue
        if arg.search(field):
            continue
        return (title + "!=" + arg.pattern,
                "%s '%s' does not match '%s'" % (title, field, arg.pattern))

    return None, None
