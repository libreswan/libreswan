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

    def __init__(self, test_directory, kind, expected_result, old_output_directory=None, testsuite_directory=None):
        self.logger = logutil.getLogger(__name__)
        # basics
        self.kind = kind
        self.expected_result = expected_result
        # The test's name is always identical to the test directory's
        # name (aka basename).  However, since TEST_DIRECTORY could be
        # relative (for instance "."  or "./..") it first needs to be
        # made absolute before the basename can be extracted.
        test_directory = os.path.abspath(test_directory)
        # The test's name is the same as the directory's basename.
        self.name = os.path.basename(test_directory)
        self.full_name = "test " + self.name
        # Construct the test's relative directory path such that it
        # always contains the test directory name (i.e., the test
        # name) as context.  For instance: "."  gets rewritten as
        # ../<test>; and ".." gets rewritten as "../../<test>".  This
        # ensures that displayed paths always include some context.
        # For instance, given "kvmresult.py .", "../<test> passed"
        # (and not ". passed") will be displayed.
        self.directory = os.path.join(os.path.relpath(os.path.dirname(test_directory)), self.name)
        # Directory where the next test run's output should be
        # written.
        self.output_directory = os.path.join(self.directory, "OUTPUT")
        self.result_file = os.path.join(self.output_directory, "RESULT")
        # Directory containing saved output from a previous test run.
        # If the test's output directory was explicitly specified, say
        # as a parameter to kvmrunner.py vis:
        #
        #   kvmresults.py testing/pluto/<test>/OUTPUT.OLD
        #   kvmresults.py testing/pluto/OUTPUT/<test>
        #
        # than that directory, and not the next output-directory,
        # should be used as a source of test results.
        self.old_output_directory = old_output_directory
        # The testsuite directory, if known.  Tests outside of a
        # testsuite do not have a testsuite_directory.
        self.testsuite_directory = testsuite_directory
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


class TestsuiteIterator:

    def __init__(self, testsuite):
        self.logger = logutil.getLogger(__name__)
        self.testsuite = testsuite
        self.logger.debug("opening '%s'", self.testsuite.testlist)
        self.testlist = open(testsuite.testlist, 'r')

    def __next__(self):
        for line in self.testlist:
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
                old_output_directory = self.testsuite.old_output_directory and os.path.join(self.testsuite.old_output_directory, name)
                test = Test(testsuite_directory=self.testsuite.directory,
                            test_directory=os.path.join(self.testsuite.directory, name),
                            old_output_directory=old_output_directory,
                            kind=kind, expected_result=expected_result)
            except ValueError:
                # This is serious
                self.logger.log(self.testsuite.error_level,
                                "****** malformed line: %s", line)
                continue
            self.logger.debug("test directory: %s", test.directory)
            if not os.path.exists(test.directory):
                # This is serious
                self.logger.log(self.testsuite.error_level,
                                "****** invalid test %s: directory not found: %s",
                                test.name, test.directory)
                continue
            return test

        self.testlist.close()
        self.logger.debug("closing '%s'", self.testsuite.testlist)
        raise StopIteration


class Testsuite:

    def __init__(self, directory, testlist, error_level, old_output_directory=None):
        self.error_level = error_level
        self.directory = directory
        self.testlist = testlist
        self.old_output_directory = old_output_directory

    def __iter__(self):
        return TestsuiteIterator(self)


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

    # Is DIRECTORY a testsuite?  For instance: testing/pluto.
    testlist = os.path.join(directory, TESTLIST)
    if os.path.exists(testlist):
        logger.debug("'%s' is a testsuite directory", directory)
        return Testsuite(directory, testlist, error_level)

    # Is DIRECTORY a testsuite sub-directory containing testsuite
    # results?  For instance: testing/pluto/OUTPUT.  Exclude the
    # possibility that the sub-directory is a single test (i.e.,
    # "testing/pluto/<test>") by checking that the file
    # description.txt is absent.
    testlist = os.path.join(directory, "..", TESTLIST)
    if os.path.exists(testlist) \
    and not os.path.exists(os.path.join(directory, "description.txt")):
        logger.debug("'%s' is an output sub-directory under a testsuite", directory)
        return Testsuite(os.path.join(directory, ".."), testlist, error_level,
                         old_output_directory=directory)

    logger.debug("'%s' does not appear to be a testsuite directory", directory)
    return None


def load_testsuite_or_tests(logger, directories, log_level=logutil.DEBUG):

    # If there is only one directory then, perhaps, it contains a full
    # testsuite.  The easiest way to find out is to try opening it.
    if len(directories) == 1:
        testsuite = load(logger, directories[0])
        if testsuite:
            logger.log(log_level, "testsuite: %s", testsuite.directory)
            return testsuite

    # There are multiple directories so, presumably, each one
    # specifies a single test that need to be "loaded".  Form a list
    # of the tests.
    tests = []
    for directory in directories:
        # Python's basename is close to useless - given "foo/" it
        # returns "" and not "foo" - get around this.
        if not os.path.basename(directory):
            directory = os.path.dirname(directory)
        test_directory = None
        old_output_directory = None
        # Use heuristics to differentiate between a directory that
        # contains a test, and an old-output directory that contains
        # test output (hopefully, for the latter, there is a test
        # directory close by).
        if os.path.exists(os.path.join(directory, "description.txt")):
            # easy case, directory is a test
            logger.debug("'%s' matches <test> - a test directory", directory)
            test_directory = directory
        elif os.path.exists(os.path.join(directory, "..", "description.txt")):
            # DIRECTORY is a sub-directory of a test so, presumably,
            # it contains old test output.  Note that the test for the
            # path DIRECTORY/.. only works when DIRECTORY exists.  See
            # also next test.
            logger.debug("'%s' matches <test>/OUTPUT - a test output sub-directory", directory)
            old_output_directory = directory
            test_directory = os.path.join(directory, "..")
        elif os.path.basename(directory).startswith("OUTPUT") \
        and os.path.exists(os.path.join(os.path.dirname(directory), "description.txt")):
            # DIRECTORY doesn't exist, yet it really really looks like
            # a test output sub-directory (if DIRECTORY did exist the
            # earlier test would have succeeded).  The sequence:
            #
            #   cd testing/pluto/<TEST>
            #   rm -rf OUTPUT
            #   kvmrunner.py !$
            #
            # will cause this.
            logger.debug("'%s' matches <test>/OUTPUT.* - a deleted test output sub-directory", directory)
            old_output_directory = directory
            test_directory = os.path.dirname(directory)
        elif os.path.exists(os.path.join(directory, "..", "..", TESTLIST)) \
        and os.path.exists(os.path.join(directory, "..", "..", os.path.basename(directory), "description.txt")):
            # DIRECTORY is old saved test output under a testsuite
            # sub-directory.  The sequence:
            #
            #   mkdir testing/pluto/OUTPUT.YYMMDD
            #   mv testing/pluto/<TEST>/OUTPUT testing/pluto/OUTPUT.YYMMDD/<TEST>
            #   kvmrunner.py !$
            #
            # will cause this.  In the future this may be kvmrunner's
            # default behaviour.
            logger.debug("'%s' matches OUTPUT/<test>  - a test output directory saved in a testsuite directory", directory)
            old_output_directory = directory
            test_directory = os.path.join(directory, "..", "..", os.path.basename(directory))
        else:
            logger.error("directory '%s' is invalid", directory)
            return None
        # Now try to find the test testsuite.
        if os.path.exists(os.path.dirname(test_directory), TESTLIST):
            testsuite_directory = os.path.dirname(directory)
        else:
            testsuite_directory = None
        tests.append(Test(testsuite_directory = testsuite_directory,
                          test_directory=test_directory,
                          old_output_directory=old_output_directory,
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
