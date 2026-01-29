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
from fab import testingdir
from fab import scripts
from fab import hosts

class Test:

    def __init__(self, test_directory, testing_directory,
                 saved_test_output_directory=None,
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
        # written.
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
            self._testing_directory = testingdir.joinpath()

        # Get an ordered list of {guest_name:,command:} to run.
        self.commands = scripts.commands(self.directory, self.logger)

        # Just assume any non-empty guests mentioned in scripts needs
        # to run.
        guests = hosts.Set()
        for command in self.commands:
            if command.guest:
                guests.add(command.guest)
        self.guests = sorted(guests)

        # remember all the platforms that are required
        platforms = hosts.Set()
        for guest in guests:
            if guest.platform:
                platforms.add(guest.platform)
        self.platforms = sorted(platforms)

    def testing_directory(self, *path):
        return os.path.relpath(os.path.join(self._testing_directory, *path))

    def __str__(self):
        return self.full_name


def add_arguments(parser):

    group = parser.add_argument_group("testsuite arguments",
                                      "options for configuring the testsuite or test directories")

    group.add_argument("--testing-directory", metavar="DIRECTORY",
                       default=testingdir.joinpath(),
                       help="directory containing 'sanitizers/', 'default-testparams.sh' and 'pluto' along with other scripts and files used to perform test postmortem; default: '%(default)s/'")
    # Required argument, so that no arguments triggers usage.
    # Everyone uses ./kvm anyway?
    group.add_argument("directories", metavar="DIRECTORY", nargs="+",
                       help="a testsuite directory, a TESTLIST file, or a list of test directories")


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


def _load_testlist(logger, log_level, args, directory):

    """Expands TESTLIST in DIRECTORY into a list of tests

    So that . (run here), and testing/ (value of KVM_TESTINGDIR) work,
    apply some fuzz when looking for TESTLIST.

    """

    # search directory, directory/TESTLIST, directory/pluto/TESTLIST,
    # ...
    head = "testing/pluto/TESTLIST"
    suffix = ""
    testlist = directory
    while True:
        if os.path.isfile(testlist):
            logger.log(log_level, "adding TESTLIST: %s", testlist)
            break
        if not head:
            logger.debug("directory does not contain TESTLIST: %s", directory)
            return None
        head, tail = os.path.split(head)
        suffix = suffix and os.path.join(tail, suffix) or tail
        testlist = os.path.join(directory, suffix)

    # DICT so duplicate checking is quick; preserve order of TESTLIST
    tests = collections.OrderedDict()
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

            test_kind = fields[0]
            test_name = fields[1]
            test_status = fields[2]
            # pr = fields[3]?

            test_directory = os.path.join(os.path.dirname(testlist), test_name)
            if not os.path.exists(test_directory):
                logger.error("****** %s:%d: invalid test %s: test directory not found: %s",
                             testlist, line_nr,
                             test_name, test_directory)
                ok = False
                continue

            if test_name in tests:
                # This is serious.
                first = tests[test_name]
                logger.error("****** %s:%d: test %s %s %s is a duplicate of %s %s %s",
                             testlist, line_nr,
                             test_kind, test_name, test_status,
                             first.kind, first.name, first.status)
                ok = False
                continue

            test = Test(kind=test_kind, status=test_status,
                        test_directory=test_directory,
                        testing_directory=args.testing_directory)
            logger.debug("test directory: %s", test.directory)
            # an OrderedDict which saves insertion order
            tests[test_name] = test

    if not ok:
        os.exit(1)

    return tests.values()


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
                testing_directory=args.testing_directory)
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

        # perhaps directory contains TESTLIST?
        testsuite = _load_testlist(logger, log_level, args, directory)
        if testsuite:
            # more efficient?
            tests.extend(testsuite)
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

    if not tests:
        logger.error("test or testsuite directory invalid: %s", args.directories)
        os.exit(1)

    return tests
