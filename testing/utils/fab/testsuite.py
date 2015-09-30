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

    def __init__(self, directory, kind, expected_result, old_output_directory=None):
        self.logger = logutil.getLogger(__name__)
        # basics
        self.kind = kind
        self.expected_result = expected_result
        # The test's name is always identical to the test's directory
        # name (aka basename).  However, since directory could be
        # relative (for instance "."  or "./..") it first needs to be
        # converted to absolute before the basename can be extracted.
        directory = os.path.abspath(directory)
        self.name = os.path.basename(directory)
        self.full_name = "test " + self.name
        # Construct a relative directory path such that it always
        # contains the actual test directory name.  For instance: "."
        # gets rewritten as ../TEST; and ".." gets rewritten as
        # "../../TEST".  This prevents optuse paths appearing in the
        # output.  For instance, it prevents "kvmresult.py ../OUTPUT"
        # printing just ".. passed".
        self.directory = os.path.join(os.path.relpath(os.path.dirname(directory)), self.name)
        # Need to juggle two directories: first, there is the
        # directory containing the OLD output from a previous test
        # run; and second, there is the directory that will contain
        # the [NEW] output from the next test run.  It makes a
        # difference when an old output directory is explicitly
        # specified. For instance, "kvmresults.py test/OUTPUT.OLD/"
        # should output the results for that directory and not
        # "test/OUTPUT/".
        self.output_directory = os.path.join(self.directory, "OUTPUT")
        self.result_file = os.path.join(self.output_directory, "RESULT")
        self.old_output_directory = old_output_directory or self.output_directory
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

    def __init__(self, testsuite, error_level):
        self.error_level = error_level
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
                self.logger.log(self.error_level,
                                "****** malformed line: %s", line)
                continue
            self.logger.debug("test directory: %s", test.directory)
            if not os.path.exists(test.directory):
                # This is serious
                self.logger.log(self.error_level,
                                "****** invalid test %s: directory not found: %s",
                                test.name, test.directory)
                continue
            return test

        self.test_list.close()
        raise StopIteration


class Testsuite:

    def __init__(self, directory, testlist, error_level):
        self.error_level = error_level
        self.directory = directory
        self.testlist = testlist

    def __iter__(self):
        return TestIterator(self, self.error_level)


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
    group.add_argument("--test-result", default="good",
                       type=re.compile, metavar="REGULAR-EXPRESSION",
                       help="Select tests with (expected) result matching %(metavar)s (default: '%(default)s')")
    group.add_argument("--test-exclude", default="",
                       type=re.compile, metavar="REGULAR-EXPRESSION",
                       help=("Exclude tests that match %(metavar)s"
                             " (default: '%(default)s')"))


def log_arguments(logger, args):
    logger.info("Testsuite arguments:")
    logger.info("  test-kind: '%s'" , args.test_kind.pattern)
    logger.info("  test-name: '%s'" , args.test_name.pattern)
    logger.info("  test-result: '%s'" , args.test_result.pattern)
    logger.info("  test-exclude: '%s'" , args.test_exclude.pattern)


TESTLIST = "TESTLIST"


def load(logger, directory, error_level=logutil.ERROR):
    """Load the testsuite (TESTLIST) found in DIRECTORY"""

    testlist = os.path.join(directory, TESTLIST)
    if os.path.exists(testlist):
        logger.debug("loading testsuite in '%s'", directory)
        return Testsuite(directory, testlist, error_level=error_level)

    return None


def load_testsuite_or_tests(logger, directories, log_level=logutil.DEBUG):

    # If there is only one directory then, perhaps, it contains a full
    # testsuite.  The easiest way to find out is to simply try loading
    # it.
    if len(directories) == 1:
        tests = load(logger, directories[0])
        if tests:
            logger.log(log_level, "tests loaded from testsuite '%s'", tests.directory)
            return tests

    # There are multiple directories so, presumably, each one
    # specifies a single test that need to be "loaded".  Form a list
    # of the tests.
    tests = []
    for directory in directories:
        # Python's basename is close to useless - given "foo/" it
        # returns "" and not "foo" - get around this.
        if not os.path.basename(directory):
            directory = os.path.dirname(directory)
        # Apply some heuristics to detect a DIRECTORY specifying an
        # the test output sub-directory and not the test directory
        # proper.
        old_output_directory = None
        if not os.path.exists(os.path.join(directory, "description.txt")) \
        and os.path.exists(os.path.join(directory, "..", "description.txt")):
            # DIRECTORY specifies an existing output sub-directory.
            # The test directory proper is just one level up. Note
            # that the relative path DIRECTORY/.. only works when
            # DIRECTORY exists.
            old_output_directory = directory
            directory = os.path.join(directory, "..")
        elif os.path.basename(directory).startswith("OUTPUT") \
        and os.path.exists(os.path.join(os.path.dirname(directory), "description.txt")):
            # DIRECTORY doesn't exist (if it did the first test would
            # pass) yet it really looks like a test OUTPUT directory.
            # The test directory proper is just dirname of DIRECTORY.
            #
            # A sequence like:
            #
            #   rm -rf OUTPUT
            #   kvmrunner.py !$
            #
            # will trigger this case
            old_output_directory = directory
            directory = os.path.dirname(directory)
        # one last sanity check
        if not os.path.exists(os.path.join(directory, "description.txt")):
            logger.error("invalid test directory: %s", old_output_directory or directory)
            return None
        # explain what is going on
        if old_output_directory:
            logger.log(log_level, "adding test directory '%s' with old output directory '%s')", directory, old_output_directory)
        else:
            logger.log(log_level, "adding test directory '%s'", directory)
        tests.append(Test(directory=directory, old_output_directory=old_output_directory,
                          kind="kvmplutotest", expected_result="good"))

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
    if args.test_result.pattern and not args.test_result.search(test.expected_result):
        return "expected test result '%s' does not match '%s'" % (test.expected_result, args.test_result.pattern)

    if args.test_exclude.pattern:
        if args.test_exclude.search(test.kind) or \
           args.test_exclude.search(test.name) or \
           args.test_exclude.search(test.expected_result):
            return "matches exclude regular expression: %s" % args.test_exclude.pattern

    return None
