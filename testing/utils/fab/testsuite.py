# Lists the tests
#
# Copyright (C) 2016-2016 Andrew Cagney <cagney@gnu.org>
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

import os
import re
import collections

from fab import logutil
from fab import utilsdir
from fab import scripts
from fab.hosts import GUEST_NAMES


class Test:

    def __init__(self, test_directory, testing_directory,
                 saved_test_output_directory=None,
                 testsuite_output_directory=None,
                 kind="kvmplutotest", status="good"):
        # basics
        self.kind = kind
        self.status = status

        # The test's name is always identical to the test directory's
        # name (aka basename).  However, since TEST_DIRECTORY could be
        # relative (for instance "."  or "./..") it first needs to be
        # made absolute before the basename can be extracted.
        test_directory = os.path.realpath(test_directory)
        # The test's name is the same as the directory's basename.
        self.name = os.path.basename(test_directory)
        self.full_name = "test " + self.name

        self.logger = logutil.getLogger(self.name)

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
        else:
            self.saved_output_directory = None

        # The testing_directory to use when performing post.mortem
        # tasks such as running the sanitizer.
        #
        # Since test.directory may be incomplete (sanitizers directory
        # may be missing), use the testing directory belonging to this
        # script.
        if testing_directory:
            # trust it
            self._testing_directory = os.path.relpath(testing_directory)
        else:
            self._testing_directory = utilsdir.relpath("..")

        # Get an ordered list of {guest_name:,command:} to run.
        self.commands = scripts.commands(self.directory, self.logger)

        # Just assume any non-empty host mentioned in scripts needs to
        # run.
        guest_names = set()
        for command in self.commands:
            if command.guest_name:
                guest_names.add(command.guest_name)
        self.guest_names = sorted(guest_names)

    def testing_directory(self, *path):
        return os.path.relpath(os.path.join(self._testing_directory, *path))

    def __str__(self):
        return self.full_name


# Load the tetsuite defined by TESTLIST

class Testsuite:

    def __init__(self, logger, testlist,
                 testing_directory,
                 testsuite_output_directory=None):
        self.directory = os.path.dirname(testlist)
        self.testlist = collections.OrderedDict()
        line_nr = 0
        ok = True
        with open(testlist, 'r') as testlist_file:
            for line in testlist_file:
                line_nr += 1
                # clean up the line, but save the original for logging
                orig = line.strip("\r\n")
                if "#" in line:
                    line = line[:line.find("#")]
                line = line.strip()
                # the two log messages should align
                if not line:
                    logger.debug("empty: %s", orig)
                    continue
                else:
                    logger.debug("input: %s", orig)
                # Extract the fields
                fields = line.split()
                if len(fields) < 3:
                    # This is serious
                    logger.error("****** %s:%d: line has too few fields: %s",
                                 testlist, line_nr, orig)
                    ok = False
                    continue
                if len(fields) > 4:
                    # This is serious
                    logger.error("****** %s:%d: line has too many fields: %s",
                                 testlist, line_nr, orig)
                    ok = False
                    continue
                kind = fields[0]
                name = fields[1]
                status = fields[2]
                # pr = fields[3]?
                test = Test(kind=kind, status=status,
                            test_directory=os.path.join(self.directory, name),
                            testsuite_output_directory=testsuite_output_directory,
                            testing_directory=testing_directory)
                logger.debug("test directory: %s", test.directory)
                if not os.path.exists(test.directory):
                    # This is serious.  However, stumble on.
                    logger.error("****** %s:%d: invalid test %s: test directory not found: %s",
                                 testlist, line_nr,
                                 test.name, test.directory)
                    ok = False
                    continue
                if test.name in self.testlist:
                    # This is serious.
                    #
                    # However, after reporting continue and select the
                    # second entry.  Preserves historic behaviour, as
                    # selecting the first entry would invalidate
                    # earlier test results.
                    first = self.testlist[test.name]
                    logger.error("****** %s:%d: test %s %s %s is a duplicate of %s %s %s",
                                 testlist, line_nr,
                                 test.kind, test.name, test.status,
                                 first.kind, first.name, first.status)
                    ok = False
                # an OrderedDict which saves insertion order
                self.testlist[test.name] = test

        if not ok:
            raise Exception("TESTLIST file %s invalid" % (testlist))

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
                       help="directory containing 'sanitizers/', 'default-testparams.sh' and 'pluto' along with other scripts and files used to perform test postmortem; default: '%(default)s/'")

    # There are two outputs: old and new; how to differentiate?
    group.add_argument("--testsuite-output", metavar="OUTPUT-DIRECTORY",
                        help="save test results in %(metavar)s/<test> instead of testing/pluto/<test>/OUTPUT")


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


def load(logger, log_level, args,
         testsuite_directory=None,
         testsuite_output_directory=None):
    """Load the single testsuite (TESTLIST) found in DIRECTORY

    A testsutite is defined by the presence of TESTLIST in DIRECTORY,
    it returns what looks like a dictionary indexable by test name.

    """

    # Is DIRECTORY a testsuite or a testlist file?  For instance:
    # testing/pluto or testing/pluto/TESTLIST.

    if os.path.isfile(testsuite_directory):
        testlist = testsuite_directory
        testsuite_directory = os.path.dirname(testsuite_directory)
        logger.log(log_level, "'%s' is a TESTLIST file", testlist)
    else:
        head = "testing/pluto"
        path = "TESTLIST"
        while True:
            testlist = os.path.join(testsuite_directory, path)
            if os.path.isfile(testlist):
                logger.log(log_level, "'%s' is a testsuite directory", testsuite_directory)
                break
            if not head:
                logger.debug("'%s' does not appear to be a testsuite directory", testsuite_directory)
                return None
            head, tail = os.path.split(head)
            path = os.path.join(tail, path)

    return Testsuite(logger, testlist,
                     testing_directory=args.testing_directory,
                     testsuite_output_directory=testsuite_output_directory or args.testsuite_output)


def append_test(logger, log_level, tests, args, directory,
                message,
                test=None,
                test_directory=None,
                saved_test_output_directory=None):
    """If it looks like a test, append it"""

    logger.debug("does '%s' contain %s?", directory, message)

    # simple checks
    if saved_test_output_directory \
    and not is_test_output_directory(saved_test_output_directory):
        return False

    if test:
        assert not test_directory
        test_directory = os.path.join(args.testing_directory, "pluto", test)

    if not test_directory:
        return False

    if not is_test_directory(test_directory):
        return False

    test = Test(test_directory=test_directory,
                saved_test_output_directory=saved_test_output_directory,
                testing_directory=args.testing_directory,
                testsuite_output_directory=args.testsuite_output)
    logger.log(log_level, "directory '%s' contains %s '%s'", directory, message, test.name)
    tests.append(test)

    return True


def load_testsuite_or_tests(logger, directories, args,
                            log_level=logutil.DEBUG):

    # Deal with each directory in turn.  It might be a test,
    # testsuite, testlist, or output.

    tests = []
    for directory in directories:

        logger.debug("is %s a test or testsuite?", directory)

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

        # kvmrunner.py testing/pluto/<test>
        if append_test(logger, log_level, tests, args, directory,
                       "the test",
                       test_directory=directory):
            continue

        # kvmrunner.py testing/pluto/<test>/OUTPUT
        #
        # This works when OUTPUT contains results.
        if os.path.basename(directory) == "OUTPUT" \
        and append_test(logger, log_level, tests, args, directory,
                       "output from the test",
                       test_directory=os.path.dirname(directory),
                       saved_test_output_directory=directory):
            continue

        # rm testing/pluto/<test>/OUTPUT/* ; kvmrunner.py testing/pluto/<test>/OUTPUT/
        # ???

        # kvmrunner.py BACKUP/YYYYMMDD/<test>/OUTPUT
        if os.path.basename(directory) == "OUTPUT" \
        and append_test(logger, log_level, tests, args, directory,
                       "saved output from the test",
                       test=os.path.basename(os.path.dirname(directory)),
                       saved_test_output_directory=directory):
            continue

        # kvmrunner.py BACKUP/YYYYMMDD/<test> [/OUTPUT/]
        if append_test(logger, log_level, tests, args, directory,
                       "OUTPUT/ which contains saved output from the test",
                       test=os.path.basename(directory),
                       saved_test_output_directory=os.path.join(directory, "OUTPUT")):
            continue

        # cp testing/pluto/<test>/OUTPUT <test> ; kvmrunner.py <test>
        if append_test(logger, log_level, tests, args, directory,
                       "saved output from the test",
                       test=os.path.basename(directory),
                       saved_test_output_directory=directory):
            continue

        # kvmrunner.py BACKUP/YYYYMMDD/ [<test>/OUTPUT]
        found = False
        for subdir in os.listdir(directory):
            if append_test(logger, log_level, tests, args, directory,
                           subdir + "/OUTPUT/ which contains saved output from the test",
                           test=subdir,
                           saved_test_output_directory=os.path.join(directory, subdir, "OUTPUT")):
                found = True
        if found:
            continue

        # kvmrunner.py BACKUP/YYYYMMDD/ [<test:OUTPUT>]
        found = False
        for subdir in os.listdir(directory):
            if append_test(logger, log_level, tests, args, directory,
                           subdir + "/ which contains saved output from the test",
                           test=subdir,
                           saved_test_output_directory=os.path.join(directory, subdir)):
                found = True
        if found:
            continue

        # rm testing/pluto/TESTLIST ; kvmrunner.py testing/pluto/
        found = False
        for subdir in os.listdir(directory):
            if append_test(logger, log_level, tests, args, directory,
                           subdir + "/ contains the test",
                           test_directory=os.path.join(directory, subdir)):
                found = True
        if found:
            continue

        logger.error("directory '%s' is invalid", directory)
        continue

    return tests
