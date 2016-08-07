# Lists the tests
#
# Copyright (C) 2016-2016 Andrew Cagney <cagney@gnu.org>
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
import collections

from fab import logutil
from fab import utilsdir
from fab import scripts
from fab.hosts import HOST_NAMES


class Test:

    def __init__(self, test_directory, testing_directory,
                 saved_test_output_directory=None,
                 saved_testsuite_output_directory=None,
                 testsuite_output_directory=None,
                 kind="kvmplutotest", expected_result="good"):
        self.logger = logutil.getLogger(__name__)
        # basics
        self.kind = kind
        self.expected_result = expected_result

        # The test's name is always identical to the test directory's
        # name (aka basename).  However, since TEST_DIRECTORY could be
        # relative (for instance "."  or "./..") it first needs to be
        # made absolute before the basename can be extracted.
        test_directory = os.path.realpath(test_directory)
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
        # written.  If a common testsuite output directory was
        # specified, use that.
        if testsuite_output_directory:
            self.output_directory = os.path.join(testsuite_output_directory, self.name)
        else:
            self.output_directory = os.path.join(self.directory, "OUTPUT")

        # Directory containing saved output from a previous test run.
        # If the test's output directory was explicitly specified, say
        # as a parameter to kvmrunner.py vis:
        #
        #   kvmresults.py testing/pluto/<test>/OUTPUT.OLD
        #   kvmresults.py testing/pluto/OUTPUT/<test>
        #
        # than that directory, and not the next output-directory, will
        # be passed in and saved here.  Otherwise it is None, and the
        # OUTPUT_DIRECTORY should be used.
        if saved_test_output_directory:
            self.saved_output_directory = saved_test_output_directory
        elif saved_testsuite_output_directory:
            self.saved_output_directory = os.path.join(saved_testsuite_output_directory, self.name)
        else:
            self.saved_output_directory = None

        # An instance of the test directory within a tree that
        # includes all the post-mortem sanitization scripts.  If the
        # test results have been copied then this will be different to
        # test.directory.
        self.sanitize_directory = os.path.realpath(os.path.join(testing_directory, "pluto", self.name))

        # Get an ordered list of (host,script) pairs of all the
        # scripts that need to be run.
        self.host_script_tuples = scripts.host_script_tuples(self.directory)

        # Just assume any host mentioned in scripts needs to run.
        self.host_names = set()
        for host, script in self.host_script_tuples:
            self.host_names.add(host)


    def result_file(self, directory=None):
        """The result file in the given directory, or output_directory"""

        directory = directory or self.output_directory
        return os.path.join(directory, "RESULT")


    def __str__(self):
        return self.full_name


# Load the tetsuite defined by TESTLIST

class Testsuite:

    def __init__(self, logger, testlist, error_level,
                 testing_directory,
                 testsuite_output_directory=None,
                 saved_testsuite_output_directory=None):
        self.directory = os.path.dirname(testlist)
        self.testlist = collections.OrderedDict()
        with open(testlist, 'r') as testlist_file:
            for line in testlist_file:
                line = line.strip()
                # these three log lines are ment to align
                if not line:
                    logger.debug("%7s: ", "blank")
                    continue
                if line[0] == '#':
                    logger.debug("%7s: %s", "comment", line)
                    continue
                logger.debug("%7s: %s", "input", line)
                try:
                    kind, name, expected_result = line.split()
                except ValueError:
                    # This is serious
                    logger.log(error_level,
                                    "****** malformed line: %s", line)
                    continue
                test = Test(kind=kind, expected_result=expected_result,
                            test_directory=os.path.join(self.directory, name),
                            saved_testsuite_output_directory=saved_testsuite_output_directory,
                            testsuite_output_directory=testsuite_output_directory,
                            testing_directory=testing_directory)
                logger.debug("test directory: %s", test.directory)
                if not os.path.exists(test.directory):
                    # This is serious
                    logger.log(error_level,
                                    "****** invalid test %s: directory not found: %s",
                                    test.name, test.directory)
                    continue
                # an OrderedDict which saves insertion order
                self.testlist[test.name] = test

    def __iter__(self):
        return self.testlist.values().__iter__()

    def __contains__(self, index):
        return index in self.testlist

    def __getitem__(self, index):
        return self.testlist[index]

    def __len__(self):
        return self.testlist.__len__()

def add_arguments(parser):

    group = parser.add_argument_group("testsuite arguments",
                                      "options for configuring the testsuite or test directories")

    group.add_argument("--testing-directory", metavar="DIRECTORY",
                       default=utilsdir.relpath(".."),
                       help="directory containg 'sanitizers/', 'default-testparams.sh' and 'pluto' along with other scripts and files used to perform test postmortem; default: '%(default)s/'")

    # There are two outputs: old and new; how to differentiate?
    group.add_argument("--testsuite-output", metavar="DIRECTORY",
                        help="save test results in%(metavar)s/<test> instead of <test>/OUTPUT")


def log_arguments(logger, args):
    logger.info("Testsuite arguments:")
    logger.info("  testing-directory: '%s'", args.testing_directory)
    logger.info("  testsuite-output: '%s'", args.testsuite_output)


def is_test_directory(directory):
    """Heuristic to detect an individual test directory"""
    for h in ["description.txt", "eastinit.sh"]:
        if os.path.exists(os.path.join(directory, h)):
            return True
    return False

def is_test_output_directory(directory):
    """Heuristic to detect a test output directory"""
    for h in ["debug.log", "east.console.verbose.txt"]:
        if os.path.exists(os.path.join(directory, h)):
            return True
    return False

TESTLIST = "TESTLIST"


def load(logger, log_level, args,
         testsuite_directory=None,
         testsuite_output_directory=None, # going away
         saved_testsuite_output_directory=None,
         error_level=logutil.ERROR):
    """Load the single testsuite (TESTLIST) found in DIRECTORY

    A testsutite is defined by the presence of TESTLIST in DIRECTORY,
    it returns what looks like a dictionary indexable by test name.

    """

    saved_testsuite_output_directory = saved_testsuite_output_directory or testsuite_output_directory
    # Is DIRECTORY a testsuite or a testlist file?  For instance:
    # testing/pluto or testing/pluto/TESTLIST.
    if os.path.isfile(testsuite_directory):
        testlist = testsuite_directory
        testsuite_directory = os.path.dirname(testsuite_directory)
        logger.log(log_level, "'%s' is a TESTLIST file", testlist)
    else:
        testlist = os.path.join(testsuite_directory, TESTLIST)
        if not os.path.exists(testlist):
            logger.debug("'%s' does not appear to be a testsuite directory", testsuite_directory)
            return None
        logger.log(log_level, "'%s' is a testsuite directory", testsuite_directory)
    return Testsuite(logger, testlist, error_level,
                     testing_directory=args.testing_directory,
                     testsuite_output_directory=args.testsuite_output,
                     saved_testsuite_output_directory=saved_testsuite_output_directory)


def append_test(tests, args, test_directory=None,
                saved_test_output_directory=None):
    """If it looks like a test, append it"""

    if saved_test_output_directory \
    and not is_test_output_directory(saved_test_output_directory):
        return False

    # Use the saved test output directory's name to find the
    # corresponding test directory.
    if not test_directory:
        if saved_test_output_directory:
            subdir = os.path.basename(saved_test_output_directory)
            test_directory = os.path.join(args.testing_directory, "pluto", subdir)
    if not test_directory:
        return False
    if not is_test_directory(test_directory):
        return False

    tests.append(Test(test_directory=test_directory,
                      saved_test_output_directory=saved_test_output_directory,
                      testing_directory=args.testing_directory,
                      testsuite_output_directory=args.testsuite_output))
    return True


def load_testsuite_or_tests(logger, directories, args,
                            log_level=logutil.DEBUG):

    # Deal with each directory in turn.  It might be a test,
    # testsuite, testlist, or output.

    tests = []
    for directory in directories:

        # Python's basename is close to useless - given "foo/" it
        # returns "" and not "foo" - get around this.
        if not os.path.basename(directory):
            logger.debug("chopping / off '%s'", directory)
            directory = os.path.dirname(directory)

        # perhaps directory/file is a testsuite?
        testsuite = load(logger, log_level, args, testsuite_directory=directory,
                         testsuite_output_directory=args.testsuite_output)
        if testsuite:
            # more efficient?
            for test in testsuite:
                tests.append(test)
            continue

        # easy case, directory is a single test
        if append_test(tests, args, test_directory=directory):
            logger.log(log_level, "'%s' is a test directory", directory)
            continue

        # DIRECTORY is a sub-directory of a test containing test
        # output.  For instance:
        #
        #     cd testing/pluto/<test>/OUTPUT
        #     kvmrunner.py .
        #
        # Note that the test for the path DIRECTORY/.. only works when
        # DIRECTORY exists.  See also below.
        if append_test(tests, args, test_directory=os.path.join(directory, ".."),
                       saved_test_output_directory=directory):
            logger.log(log_level, "'%s' is an output sub-directory of a test directory", directory)
            continue

        # DIRECTORY is a sub-directory of a test, yet doesn't appear
        # to contain test output.
        if not is_test_output_directory(directory) \
        and append_test(tests, args, test_directory=os.path.join(directory, "..")):
            logger.log(log_level, "'%s' is a non-output sub-directory of a test directory", directory)
            continue

        # DIRECTORY doesn't exist, yet it really really looks like a
        # test output sub-directory (if DIRECTORY did exist the
        # earlier tests would have succeeded).  The sequence:
        #
        #   rm -rf testing/pluto/<test>/OUTPUT
        #   kvmrunner.py !$
        #
        # will cause this.
        if os.path.basename(directory).startswith("OUTPUT") \
        and not os.path.exists(directory) \
        and append_test(tests, args, test_directory=os.path.dirname(directory)):
            logger.log(log_level, "'%s' is a deleted OUTPUT* sub-directory of a test directory", directory)
            continue

        # DIRECTORY is a test output directory for an unknown test.  The sequence:
        #
        #   mv testing/pluto/<test>/OUTPUT BACKUP/YYYYMMDD/<test>
        #   kvmrunner.py BACKUP/YYYYMMDD/<test>
        #
        # will cause this.  See also test below.
        if append_test(tests, args, saved_test_output_directory=directory):
            logger.log(log_level, "'%s' is a saved test output directory", directory)
            continue

        # DIRECTORY is a testsuite output directory containing <test>
        # output sub-directories.  The sequence:
        #
        #   mv testing/pluto/<test>/OUTPUT BACKUP/YYYYMMDD/<test>
        #   kvmrunner.py BACKUP/YYYYMMDD/
        #
        # will cause this.  Go through the directory looking for
        # anything that looks like test output.
        saved_testsuite = False
        for subdir in os.listdir(directory):
            if append_test(tests, args, saved_test_output_directory=os.path.join(directory, subdir)):
                logger.log(log_level, "'%s' is a saved testsuite output directory containing test '%s'", directory, subdir)
                saved_testsuite = True
        if saved_testsuite:
            continue

        logger.error("directory '%s' is invalid", directory)
        continue

    return tests
