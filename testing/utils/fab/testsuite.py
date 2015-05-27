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
import sys
import re
from enum import Enum
from fab import logutil

class TestResult:

    def __init__(self, test, message, *args):
        self.reason = message % args
        self.details = "%s, %s" % (self.value, self.reason)
        test.logger.debug("%s: %s", test.name, self.value, self.reason)

    def __bool__(self):
        return issubclass(self.__class__, TestPassed)

    def __str__(self):
        return self.details

class TestNotStarted(TestResult):
    value = "not started"
class TestNotFinished(TestResult):
    value = "not finished"
class TestFailed(TestResult):
    value = "failed"
class TestPassed(TestResult):
    value = "passed"


class Test:

    def __init__(self, testsuite, line):
        self.logger = logutil.getLogger(__name__)
        self.kind, self.name, self.expected_result = line.split()
        self.full_name = "test " + self.name
        self.testsuite = testsuite
        self.directory = os.path.join(testsuite.directory, self.name)
        self.output_directory = os.path.join(self.directory, "OUTPUT")
        self.result_file = os.path.join(self.output_directory, "RESULT")
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

    def result(self):
        self.logger.debug("output dir? %s", self.output_directory)
        if not os.path.exists(self.output_directory):
            return TestNotStarted(self, "%s directory missing", self.output_directory)

        # XXX: Look at self.result_file?

        # For every {domain}.console.txt check for a corresponding
        # OUTPUT/{domain}.console.diff.  If any are missing, the
        # test didn't complete.
        diffs = []
        for domain in self.domain_names():
            txt = os.path.join(self.directory, domain + ".console.txt")
            self.logger.debug("console.txt? %s", txt)
            if not os.path.exists(txt):
                self.logger.debug("%s does not expect results", domain)
                continue
            diff = os.path.join(self.output_directory, domain + ".console.diff")
            diffs.append(diff)
            self.logger.debug("console.diff? %s", diff)
            if not os.path.exists(diff):
                return TestNotFinished(self, "%s missing", diff)

        # Check the size of {domain}.console.diff files.  If any are
        # non-empty, the test failed.
        for diff in diffs:
            if os.stat(diff).st_size:
                return TestFailed(self, "%s non-empty", diff)

        return TestPassed(self, "all diff files empty")

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
                test = Test(self.testsuite, line)
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


TESTLIST = "TESTLIST"


class Testsuite:

    def __init__(self, directory, testlist=TESTLIST):
        self.directory = directory
        self.testlist = os.path.join(directory, testlist)

    def __iter__(self):
        return TestIterator(self)

    def __getitem__(self, name):
        for test in self:
            if test.name == name:
                return test
        return None



def _directory():
    # Detect a script run from a testsuite(./TESTLIST) or
    # test(../TESTLIST) directory.  Fallback is the pluto directory
    # next to the script's directory.
    utils_directory = os.path.dirname(sys.argv[0])
    pluto_directory = os.path.join(utils_directory, "..", "pluto")
    for directory in [".", "..", pluto_directory]:
        if os.path.exists(os.path.join(directory, TESTLIST)):
            return os.path.abspath(directory)
    return None
DEFAULT_DIRECTORY = _directory()

def _test_name_pattern():
    if os.path.exists(os.path.join("..", TESTLIST)):
        return "^" + os.path.basename(os.getcwd()) + "$"
    else:
        return ''

def add_arguments(parser):

    parser.add_argument("--testsuite-directory", default=DEFAULT_DIRECTORY,
                        help="default: %(default)s")

    parser.add_argument("--test-name", default=_test_name_pattern(), type=re.compile,
                        help=("Limit run to name tests"
                              " (default: %(default)s)"))
    parser.add_argument("--test-kind", default="kvmplutotest", type=re.compile,
                        help=("Limit run to kind tests"
                              " (default: %(default)s)"))
    parser.add_argument("--test-expected-result", default="good", type=re.compile,
                        help=("Limit run to expected-result tests"
                              " (default: %(default)s)"))
    parser.add_argument("--exclude", default='', type=re.compile,
                        help=("Exclude tests that match <regex>"
                              " (default: %(default)s)"))


def log_arguments(logger, args):
    logger.info("Testsuite arguments:")
    logger.info("  testsuite-directory: %s" , args.testsuite_directory)
    logger.info("  test-kind: '%s'" , args.test_kind.pattern)
    logger.info("  test-name: '%s'" , args.test_name.pattern)
    logger.info("  test-result: '%s'" , args.test_expected_result.pattern)
    logger.info("  exclude: '%s'" , args.exclude.pattern)


def skip(test, args):

    if args.test_kind.pattern and not args.test_kind.search(test.kind):
        return "kind '%s' does not match '%s'" % (test.kind, args.test_kind.pattern)
    if args.test_name.pattern and not args.test_name.search(test.name):
        return "name '%s' does not match '%s'" % (test.name, args.test_name.pattern)
    if args.test_expected_result.pattern and not args.test_expected_result.search(test.expected_result):
        return "expected test result '%s' does not match '%s'" % (test.expected_result, args.test_expected_result.pattern)

    if args.exclude.pattern:
        if args.exclude.search(test.kind) or \
           args.exclude.search(test.name) or \
           args.exclude.search(test.expected_result):
            return "matches exclude regular expression: %s" % args.exclude.pattern

    return None
