# Lists the tests
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

import os
import re
from fab import logutil
from fab import utils

class Test:

    def __init__(self, directory, kind, expected_result):
        self.logger = logutil.getLogger(__name__)
        # basics
        self.kind = kind
        self.expected_result = expected_result
        # name must match the directory's basename; since directory
        # could be ".", need to first convert it to an absolute path.
        self.name = os.path.basename(os.path.abspath(directory))
        self.full_name = "test " + self.name
        # avoid "." as a directory, construct the sub-directory paths
        # using the parent's directory (don't abspath or relpath).
        self.directory = os.path.relpath(directory)
        if self.directory == ".":
            self.directory = os.path.join("..", self.name)
        self.output_directory = os.path.join(self.directory, "OUTPUT")
        self.result_file = os.path.join(self.output_directory, "RESULT")
        # will be filled in later
        self.domains = None
        self.initiators = None

    def __str__(self):
        return self.full_name

    def files_with_suffix(self, suffix):
        s = set()
        for file in os.listdir(self.directory):
            host, init, t = file.partition(suffix)
            if init and not t:
                s.add(host)
        return s

    def domain_names(self):
        if not self.domains:
            self.domains = self.files_with_suffix("init.sh")
        return self.domains

    def initiator_names(self):
        if not self.initiators:
            self.initiators = self.files_with_suffix("run.sh")
        return self.initiators


class TestIterator:

    def __init__(self, testsuite):
        self.logger = logutil.getLogger(__name__)
        self.testsuite = testsuite
        self.test_list = open(testsuite.testlist, 'r')

    def __next__(self):
        for line in self.test_list:
            line = line.strip()
            self.logger.debug("input: %s", line)
            if not line:
                self.logger.debug("ignore blank line")
                continue
            if line[0] == '#':
                self.logger.debug("ignore comment line")
                continue
            try:
                kind, name, expected_result = line.split()
                test = Test(directory=os.path.join(self.testsuite.directory, name),
                            kind=kind, expected_result=expected_result)
            except ValueError:
                # This is serious
                self.logger.error("****** malformed line: %s", line)
                continue
            self.logger.debug("test directory: %s", test.directory)
            if not os.path.exists(test.directory):
                # This is serious
                self.logger.error("****** invalid test %s: directory not found: %s",
                              test.name, test.directory)
                continue
            return test

        self.test_list.close()
        raise StopIteration


class Testsuite:

    def __init__(self, directory, testlist):
        self.directory = directory
        self.testlist = testlist

    def __iter__(self):
        return TestIterator(self)


def add_arguments(parser):

    group = parser.add_argument_group("Test arguments",
                                      "Options for selecting the tests to run")
    group.add_argument("--test-name", default="",
                       type=re.compile, metavar="REGULAR-EXPRESSION",
                       help=("Select tests with name matching %(metavar)s"
                             " (default: '%(default)s')"))
    group.add_argument("--test-kind", default="kvmplutotest",
                       type=re.compile, metavar="REGULAR-EXPRESSION",
                       help=("Select tests with kind matching %(metavar)s"
                             " (default: '%(default)s')"))
    group.add_argument("--test-expected-result", default="good",
                       type=re.compile, metavar="REGULAR-EXPRESSION",
                       help=("Select tests with expected-result matching %(metavar)s"
                             " (default: '%(default)s')"))
    group.add_argument("--test-exclude", default="",
                       type=re.compile, metavar="REGULAR-EXPRESSION",
                       help=("Exclude tests that match %(metavar)s"
                             " (default: '%(default)s')"))


def log_arguments(logger, args):
    logger.info("Testsuite arguments:")
    logger.info("  test-kind: '%s'" , args.test_kind.pattern)
    logger.info("  test-name: '%s'" , args.test_name.pattern)
    logger.info("  test-result: '%s'" , args.test_expected_result.pattern)
    logger.info("  test-exclude: '%s'" , args.test_exclude.pattern)


TESTLIST = "TESTLIST"


def load(logger, directory):
    """Load the testsuite (TESTLIST) found in DIRECTORY"""

    testlist = os.path.join(directory, TESTLIST)
    if os.path.exists(testlist):
        logger.debug("loading testsuite in '%s'", directory)
        return Testsuite(directory, testlist)

    return None


def load_testsuite_or_tests(logger, directories):

    # Is it a single testsuite directory?
    if len(directories) == 1:
        tests = load(logger, directories[0])
        if tests:
            logger.debug("tests loaded from testsuite '%s'", tests.directory)
            return tests

    # Presumably this is a list of directories, each specifying one
    # test.
    tests = []
    for directory in directories:
        # XXX: Should figure out kind by looking at directory.  Should
        # validate that it is a test directory.
        logger.debug("test loaded from directory '%s'", directory)
        tests.append(Test(directory=directory, kind="kvmplutotest",
                          expected_result="good"))

    return tests


def ignore(test, args):

    """Identify tests that should be ignored due to filters

    The ignore reason is returned.

    This is different to SKIP where a test isn't run because it has
    been run before.

    """

    if args.test_kind.pattern and not args.test_kind.search(test.kind):
        return "kind '%s' does not match '%s'" % (test.kind, args.test_kind.pattern)
    if args.test_name.pattern and not args.test_name.search(test.name):
        return "name '%s' does not match '%s'" % (test.name, args.test_name.pattern)
    if args.test_expected_result.pattern and not args.test_expected_result.search(test.expected_result):
        return "expected test result '%s' does not match '%s'" % (test.expected_result, args.test_expected_result.pattern)

    if args.test_exclude.pattern:
        if args.test_exclude.search(test.kind) or \
           args.test_exclude.search(test.name) or \
           args.test_exclude.search(test.expected_result):
            return "matches exclude regular expression: %s" % args.test_exclude.pattern

    return None
