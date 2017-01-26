# Perform post.mortem on a test result, for libreswan.
#
# Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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
import subprocess
import difflib

from fab import logutil


class Resolution:
    PASSED = "passed"
    FAILED = "failed"
    UNRESOLVED = "unresolved"
    UNTESTED = "untested"
    UNSUPPORTED = "unsupported"
    def __init__(self):
        self.state = None
    def __str__(self):
        return self.state
    def __eq__(self, rhs):
        return self.state == rhs
    def unsupported(self):
        assert(self.state in [None])
        self.state = self.UNSUPPORTED
    def untested(self):
        assert(self.state in [None])
        self.state = self.UNTESTED
    def passed(self):
        assert(self.state in [None])
        self.state = self.PASSED
    def failed(self):
        assert(self.state in [self.FAILED, self.PASSED, self.UNRESOLVED])
        if self.state in [self.FAILED, self.PASSED]:
            self.state = self.FAILED
    def unresolved(self):
        assert(self.state in [self.PASSED, self.FAILED, self.UNRESOLVED, None])
        self.state = self.UNRESOLVED


# Dictionary to accumulate all the errors for each host from an
# individual test.

class Issues:

    def __init__(self, logger):
        # Structure needs to be JSON friendly.
        self.issues = {}
        self.logger = logger

    # this formatting is subject to infinite feedback.
    #
    # Not exactly efficient.
    def __str__(self):
        s = ""
        for host, errors in sorted(self.issues.items()):
            if s:
                s += " "
            if host:
                s += host + ":"
            s += ",".join(sorted(errors))
        return s

    def json(self):
        return self.issues

    # So, like a real collection, can easily test if non-empty.
    def __bool__(self):
        return len(self.issues) > 0

    # Iterate over the actual errors, not who had them.
    #
    # XXX: there's not much consistency between __iter__(), items(),
    # __contains__() and __getitem__().  On the other hand, a hashmap
    # iter isn't consistent either.
    def __iter__(self):
        values = set()
        for errors in self.issues.values():
            for error in errors:
                values |= error
        return values.__iter__()

    def __contains__(self, item):
        return item in self.issues

    def __getitem__(self, item):
        return self.issues[item]

    def items(self):
        return self.issues.items()

    def add(self, error, host):
        if not host in self.issues:
            self.issues[host] = []
        if not error in self.issues[host]:
            self.issues[host].append(error)
        self.logger.debug("host %s has error %s", host, error)

    def search(self, regex, string, error, host):
        self.logger.debug("searching host %s for '%s' (error %s)", host, regex, error)
        if re.search(regex, string):
            self.add(error, host)
            return True
        else:
            return False

    def grep(self, regex, filename, error, host):
        self.logger.debug("grepping host %s file '%s' for '%s' (error %s)", host, filename, regex, error)
        command = ['grep', '-e', regex, filename]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode or stderr:
            return False
        self.add(error, host)
        return True

def _strip(s):
    s = re.sub(r"[ \t]+", r"", s)
    s = re.sub(r"\n+", r"\n", s)
    s = re.sub(r"^\n", r"", s)
    return s

def _whitespace(l, r):
    """Return true if L and R are the same after stripping white space"""
    return _strip(l) == _strip(r)

def _diff(logger, ln, l, rn, r):
    """Return the difference between two strings"""

    if l == r:
        # slightly faster path
        logger.debug("_diff '%s' and '%s' fast match", ln, rn)
        return []
    # compare
    diff = list(difflib.unified_diff(l.splitlines(), r.splitlines(),
                                     fromfile=ln, tofile=rn,
                                     lineterm=""))
    logger.debug("_diff: %s", diff)
    if not diff:
        # Always return a list.
        return []
    return diff


def _sanitize_output(logger, raw_file, test):
    # Run the sanitizer found next to the test_sanitize_directory.
    command = [
        test.testing_directory("utils", "sanitizer.sh"),
        raw_file,
        test.testing_directory("pluto", test.name)
    ]
    logger.debug("sanitize command: %s", command)
    # Note: It is faster to re-read the file than read the
    # pre-loaded raw console output.
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    logger.debug("sanitized output:\n%s", stdout)
    if process.returncode or stderr:
        # any hint of an error
        logger.error("sanitize command '%s' failed; exit code %s; stderr: '%s'",
                     command, process.returncode, stderr.decode("utf8"))
        return None
    return stdout.decode("utf-8")


def _load_file(logger, filename):
    """Load the specified file; return None if it does not exist"""

    if os.path.exists(filename):
        logger.debug("loading file: %s", filename)
        with open(filename) as f:
            return f.read()
    else:
        logger.debug("file %s does not exist", filename)
    return None


# The TestResult objects are almost, but not quite, an enum. It
# carries around additional result details.

class TestResult:

    def __str__(self):
        return str(self.resolution)

    def __bool__(self):
        """True if the test was attempted.

        That is POSIX 1003.3 PASS, FAIL, or UNRESOLVED (which leaves
        UNTESTED).

        """
        return self.resolution in [self.resolution.PASSED, self.resolution.FAILED, self.resolution.UNRESOLVED]

    def __init__(self, logger, test, quick, update=None,
                 output_directory=None, finished=None):

        # Set things up for passed
        self.logger = logger
        self.test = test
        self.resolution = Resolution()
        self.issues = Issues(self.logger)
        self.diffs = {}
        self.sanitized_output = {}

        output_directory = output_directory or test.output_directory

        # If there is no OUTPUT directory the result is UNTESTED -
        # presence of the OUTPUT is a clear indicator that some
        # attempt was made to run the test.
        if not os.path.exists(output_directory):
            self.resolution.untested()
            self.logger.debug("output directory missing: %s", output_directory)
            return

        # Did the test finish (resolved)?
        #
        # If a test is unfinished (for instance, aborted, or in
        # progress) then it should be marked as UNRESOLVED.
        #
        # Something other than RESULT is needed as a way to detect a
        # finished test.

        if finished is None:
            # For moment use the presence of the RESULT file as a
            # proxy for a test being resolved.
            finished = os.path.isfile(test.result_file(output_directory))
        if finished:
            # Start out assuming that it passed and then prove
            # otherwise.
            self.resolution.passed()
        else:
            # Something is known to be wrong.  Start out with failed.
            self.resolution.unresolved()

        # crash or other unexpected behaviour.
        for host_name in test.host_names:
            pluto_log = os.path.join(output_directory, host_name + ".pluto.log")
            if os.path.exists(pluto_log):
                self.logger.debug("checking '%s' for errors", pluto_log)
                if self.issues.grep("ASSERTION FAILED", pluto_log, "ASSERTION", host_name):
                    self.resolution.failed()
                # XXX: allow expection failures?
                self.issues.grep("EXPECTATION FAILED", pluto_log, "EXPECTATION", host_name)

        # Check the raw console output for problems and that it
        # matches expected output.
        for host_name in test.host_names:

            # Try to load this hosts's raw console output.

            raw_output_filename = os.path.join(output_directory,
                                               host_name + ".console.verbose.txt")
            self.logger.debug("host %s raw console output '%s'",
                              host_name, raw_output_filename)
            raw_output = _load_file(self.logger, raw_output_filename)

            # Check that the host's raw output is present.
            #
            # If there is no output at all then the test crashed badly
            # (for instance, while trying to boot domains).
            #
            # Since things really screwed up, mark the test as
            # UNRESOLVED and give up.

            if raw_output is None:
                self.issues.add("output-missing", host_name)
                self.resolution.unresolved()
                # With no raw console output, there's little point in
                # trying validating it.  Skip remaining tests for this
                # host.
                continue

            # Check the host's raw output for signs of a crash.

            self.logger.debug("host %s checking raw console output for signs of a crash",
                              host_name)
            if self.issues.search(r"[\r\n]CORE FOUND", raw_output, "CORE", host_name):
                self.resolution.failed()
            if self.issues.search(r"SEGFAULT", raw_output, "SEGFAULT", host_name):
                self.resolution.failed()
            if self.issues.search(r"GPFAULT", raw_output, "GPFAULT", host_name):
                self.resolution.failed()

            # Check that the host's raw output is complete.
            #
            # The output can become truncated for several reasons: the
            # test is a work-in-progress; it crashed due to a timeout;
            # or it is still being run.
            #
            # Don't try to match the prompt ("#").  If this is the
            # first command in the script, the prompt will not appear
            # in the output.
            #
            # When this happens, mark it as a FAIL.  The
            # test-in-progress case was hopefully handled further back
            # with the RESULT hack forcing the test to UNRESOLVED.

            ending = ": ==== end ===="
            logger.debug("host %s checking if raw console output contains %s",
                         host_name, ending)
            if not ending in raw_output:
                self.issues.add("output-truncated", host_name)
                self.resolution.failed()
                # Should this skip the remaining tests?  No.
                # Sanitizing the output is still useful here.

            # Sanitize what ever output there is and save it.

            sanitized_output_filename = os.path.join(output_directory,
                                                     host_name + ".console.txt")
            self.logger.debug("host %s sanitize console output '%s'",
                              host_name, sanitized_output_filename)
            sanitized_output = None
            if quick:
                sanitized_output = _load_file(self.logger,
                                              sanitized_output_filename)
            if sanitized_output is None:
                sanitized_output = _sanitize_output(self.logger,
                                                    raw_output_filename,
                                                    test)
            if sanitized_output is None:
                self.issues.add("sanitizer-failed", host_name)
                continue
            if update:
                self.logger.debug("host %s updating sanitized output file: %s",
                                  host_name, sanitized_output_filename)
                with open(sanitized_output_filename, "w") as f:
                    f.write(sanitized_output)

            self.sanitized_output[host_name] = sanitized_output

            expected_output_filename = test.testing_directory("pluto", test.name,
                                                              host_name + ".console.txt")
            self.logger.debug("host %s comparing against known-good output '%s'",
                              host_name, expected_output_filename)

            expected_output = _load_file(self.logger, expected_output_filename)
            if expected_output is None:
                self.issues.add("output-unchecked", host_name)
                self.resolution.unresolved()
                continue

            diff = None
            diff_filename = os.path.join(output_directory, host_name + ".console.diff")

            if quick:
                # Try to load the existing diff file.  Like _diff()
                # save a list of lines.
                diff = _load_file(self.logger, diff_filename)
                if diff is not None:
                    diff = diff.splitlines()

            if diff is None:
                # use brute force
                diff = _diff(self.logger,
                             "MASTER/" + test.name + "/" + host_name + ".console.txt",
                             expected_output,
                             "OUTPUT/" + test.name + "/" + host_name + ".console.txt",
                             sanitized_output)

            if update:
                self.logger.debug("host %s updating diff file %s",
                                  host_name, diff_filename)
                # Always create the diff file; when there is no diff
                # leave it empty.
                with open(diff_filename, "w") as f:
                    if diff:
                        for line in diff:
                            f.write(line)
                            f.write("\n")

            if diff:
                self.diffs[host_name] = diff
                whitespace = _whitespace(expected_output,
                                         sanitized_output)
                self.resolution.failed()
                if whitespace:
                    self.issues.add("output-whitespace", host_name)
                else:
                    self.issues.add("output-different", host_name)


# XXX: given that most of args are passed in unchagned, this should
# change to some type of result factory.

def mortem(test, args, domain_prefix="", finished=None,
           baseline=None, output_directory=None,
           quick=False, update=False):

    logger = logutil.getLogger(domain_prefix, __name__, test.name)

    test_result = TestResult(logger, test, quick,
                             output_directory=output_directory,
                             finished=finished,
                             update=update)

    if not test_result:
        return test_result

    if not baseline:
        return test_result

    # For "baseline", the general idea is that "kvmresults.py | grep
    # baseline" should print something when either a regression or
    # progression has occurred.  For instance:
    #
    #    - a test passing but the baseline failing
    #
    #    - a test failing, but the baseline passing
    #
    #    - a test failing, and the baseline failling in a different way
    #
    # What isn't interesting is a test and the baseline failing the
    # same way.

    if not test.name in baseline:
        test_result.issues.add("absent", "baseline")
        return test_result

    # When loading the baseline results use "quick" so that the
    # original results are used.  This seems to be the best of a bad
    # bunch.
    #
    # Since that the baseline was generated using an old sanitizer and
    # reference output, using the latest sanitizer scripts (in
    # testing/) can, confusingly, lead to baselines results being
    # identified as failures failing yet the diffs show a pass.
    #
    # OTOH, when this goes to compare the results against the
    # baseline, first putting them through the latest sanitizer tends
    # to result in better diffs.

    base = baseline[test.name]
    baseline_result = TestResult(logger, base, quick=True)

    if not baseline_result.resolution in [test_result.resolution.PASSED,
                                          test_result.resolution.FAILED]:
        test_result.issues.add(str(baseline_result), "baseline")
        return test_result

    if test_result.resolution in [test_result.resolution.PASSED] \
    and baseline_result.resolution in [baseline_result.resolution.PASSED]:
        return test_result

    for host_name in test.host_names:

        if not host_name in test_result.sanitized_output:
            continue

        if not host_name in baseline_result.sanitized_output:
            test_result.issues.add("baseline-missing", host_name)
            continue

        if not host_name in test_result.diffs:
            if host_name in baseline_result.diffs:
                test_result.issues.add("baseline-failed", host_name)
            continue

        if not host_name in baseline_result.diffs:
            test_result.issues.add("baseline-passed", host_name)
            continue

        baseline_diff = _diff(logger,
                              "BASELINE/" + test.name + "/" + host_name + ".console.txt",
                              baseline_result.sanitized_output[host_name],
                              "OUTPUT/" + test.name + "/" + host_name + ".console.txt",
                              test_result.sanitized_output[host_name])
        if baseline_diff:
            baseline_whitespace = _whitespace(baseline_result.sanitized_output[host_name],
                                              test_result.sanitized_output[host_name])
            if baseline_whitespace:
                test_result.issues.add("baseline-whitespace", host_name)
            else:
                test_result.issues.add("baseline-different", host_name)
            # update the diff to something hopefully closer?
            test_result.diffs[host_name] = baseline_diff
        # else:
        #    test_result.issues.add("baseline-failed", host_name)

    return test_result
