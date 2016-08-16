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

from fab import utilsdir
from fab import logutil


# Dictionary to accumulate all the errors for each host from an
# individual test.

class Errors:

    def __init__(self, logger):
        # Structure needs to be JSON friendly.
        self.errors = {}
        self.logger = logger

    # this formatting is subject to infinite feedback.
    #
    # Not exactly efficient.
    def __str__(self):
        s = ""
        for host, errors in sorted(self.errors.items()):
            if s:
                s += " "
            if host:
                s += host + ":"
            s += ",".join(sorted(errors))
        return s

    def json(self):
        return self.errors

    # So, like a real collection, can easily test if non-empty.
    def __bool__(self):
        return len(self.errors) > 0

    # Iterate over the actual errors, not who had them.
    #
    # XXX: there's not much consistency between __iter__(), items(),
    # __contains__() and __getitem__().  On the other hand, a hashmap
    # iter isn't consistent either.
    def __iter__(self):
        values = set()
        for errors in self.errors.values():
            for error in errors:
                values |= error
        return values.__iter__()

    def __contains__(self, item):
        return item in self.errors

    def __getitem__(self, item):
        return self.errors[item]

    def items(self):
        return self.errors.items()

    def add(self, error, host):
        if not host in self.errors:
            self.errors[host] = []
        if not error in self.errors[host]:
            self.errors[host].append(error)
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

# Compare two strings.  Returns:
#
#    [], None
#    [diff..], True # if white space only
#    [diff...], False
def fuzzy_diff(logger, ln, l, rn, r):
    if l == r:
        # fast path
        logger.debug("fuzzy_diff fast match")
        return [], None
    # compare
    diff = list(difflib.unified_diff(l.splitlines(), r.splitlines(),
                                     fromfile=ln, tofile=rn,
                                     lineterm=""))
    logger.debug("fuzzy_diff: %s", diff)
    if not diff:
        return [], None
    # if the problem was just white space, return that as well
    return diff, _strip(l) == _strip(r)


def sanitize_output(logger, raw_file, test_directory):
    command = [ utilsdir.relpath("sanitizer.sh"), raw_file, test_directory ]
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
                     command, process.returncode, stderr)
        return None
    return stdout.decode("utf-8")


def load_output(logger, output_file):
    if os.path.exists(output_file):
        logger.debug("loading pre-generated file: %s", output_file)
        with open(output_file) as f:
            return f.read()
    else:
        logger.debug("no pre-generated file to load: %s", output_file)
    return None


# The TestResult objects are almost, but not quite, an enum. It
# carries around additional result details.

class TestResult:

    def __str__(self):
        if self.finished is True:
            if self.passed is True:
                return "passed"
            elif self.passed is False:
                return "failed"
            else:
                return "unknown"
        elif self.finished is False:
            # Per POSIX 1003.3, the test has an indeterminate result.
            # Typically because the test aborted with a timeout, but
            # could also be due to a test still running.
            return "unresolved"
        else:
            return "untested"

    def __bool__(self):
        """True if the test was attempted.

        That is POSIX 1003.3 PASS, FAIL, or UNRESOLVED (which leaves
        UNTESTED).

        """
        return self.finished is not None

    def __init__(self, logger, test, quick, update=None,
                 output_directory=None, finished=None):

        # Set things up for an UNTESTED result
        self.logger = logger
        self.test = test
        self.passed = None
        self.finished = None
        self.errors = Errors(self.logger)
        self.diffs = {}
        self.sanitized_console_output = {}

        output_directory = output_directory or test.output_directory

        # If there is no OUTPUT directory the result is UNTESTED -
        # presence of the OUTPUT is a clear indicator that some
        # attempt was made to run the test.
        if not os.path.exists(output_directory):
            self.logger.debug("output directory missing: %s", output_directory)
            return

        self.finished = finished;
        if self.finished is None:
            # Use RESULT as a proxy for a test resolved.  It isn't
            # 100% reliable since an in-progress test looks list like
            # an aborted test.  Arguably only "good" tests should
            # resolve.
            self.finished = os.path.isfile(test.result_file(output_directory));

        # Be optimistic; passed is only really valid when resolved is
        # True.
        self.passed = True

        # crash or other unexpected behaviour.
        for host_name in test.host_names:
            pluto_log = os.path.join(output_directory, host_name + ".pluto.log")
            if os.path.exists(pluto_log):
                self.logger.debug("checking '%s' for errors", pluto_log)
                if self.errors.grep("ASSERTION FAILED", pluto_log, "ASSERTION", host_name):
                    self.passed = False
                # XXX: allow expection failures?
                self.errors.grep("EXPECTATION FAILED", pluto_log, "EXPECTATION", host_name)

        # Check the raw console output for problems and that it
        # matches expected output.
        for host_name in test.host_names:

            # There should always be raw console output from all
            # hosts.  If there isn't then there's a big problem and
            # little point with continuing checks for this host.

            raw_console_file = os.path.join(output_directory,
                                            host_name + ".console.verbose.txt")
            self.logger.debug("host %s raw console output '%s'",
                              host_name, raw_console_file)
            if not os.path.exists(raw_console_file):
                self.errors.add("output-missing", host_name)
                self.passed = False
                continue

            self.logger.debug("host %s loading raw console output", host_name)
            with open(raw_console_file) as f:
                raw_console_output = f.read()

            self.logger.debug("host %s checking raw console output for signs of a crash",
                              host_name)
            if self.errors.search(r"[\r\n]CORE FOUND", raw_console_output, "CORE", host_name):
                # keep None
                self.passed = False
            if self.errors.search(r"SEGFAULT", raw_console_output, "SEGFAULT", host_name):
                # keep None
                self.passed = False
            if self.errors.search(r"GPFAULT", raw_console_output, "GPFAULT", host_name):
                # keep None
                self.passed = False

            # Incomplete output won't match expected output so skip
            # any comparisons.
            #
            # For moment skip this as the marker for complete output isn't reliable?

            #logger.debug("host %s checking if raw console output was incomplete", host_name)
            #if not "# : ==== end ====" in raw_console_output:
            #    self.errors.add("output-incomplete", host_name)
            #    self.passed = False
            #    continue

            sanitized_console_file = os.path.join(output_directory,
                                                  host_name + ".console.txt")
            self.logger.debug("host %s sanitize console output '%s'",
                              host_name, sanitized_console_file)
            sanitized_console_output = None
            if quick:
                sanitized_console_output = load_output(self.logger, sanitized_console_file)
            if sanitized_console_output is None:
                sanitized_console_output = sanitize_output(self.logger, raw_console_file,
                                                           test.sanitize_directory)
            if sanitized_console_output is None:
                self.errors.add("sanitizer-failed", host_name)
                continue
            if update:
                self.logger.debug("host %s updating sanitized output file: %s",
                                  host_name, sanitized_console_file)
                with open(sanitized_console_file, "w") as f:
                    f.write(sanitized_console_output)

            self.sanitized_console_output[host_name] = sanitized_console_output

            expected_sanitized_console_output_file = os.path.join(test.sanitize_directory, host_name + ".console.txt")
            self.logger.debug("host %s comparing against known-good output '%s'",
                              host_name, expected_sanitized_console_output_file)
            if os.path.exists(expected_sanitized_console_output_file):

                diff, whitespace = None, None

                sanitized_console_diff_file = os.path.join(output_directory, host_name + ".console.diff")
                if quick:
                    sanitized_console_diff = load_output(logger, sanitized_console_diff_file)
                    # be consistent with fuzzy_diff which returns a list
                    # of lines.
                    #
                    # This has no easy way to detect whitespace differences, so set it to None
                    if sanitized_console_diff is not None:
                        diff, whitespace = sanitized_console_diff.splitlines(), None
                if diff is None:
                    with open(expected_sanitized_console_output_file) as f:
                        expected_sanitized_console_output = f.read()
                    diff, whitespace = fuzzy_diff(self.logger,
                                                  "MASTER/" + test.name + "/" + host_name + ".console.txt",
                                                  expected_sanitized_console_output,
                                                  "OUTPUT/" + test.name + "/" + host_name + ".console.txt",
                                                  sanitized_console_output)
                if update:
                    self.logger.debug("host %s updating diff file %s",
                                      host_name, sanitized_console_diff_file)
                    with open(sanitized_console_diff_file, "w") as f:
                        if diff:
                            for line in diff:
                                f.write(line)
                                f.write("\n")
                if diff:
                    self.diffs[host_name] = diff
                    if whitespace:
                        self.errors.add("output-whitespace", host_name)
                    else:
                        self.passed = False
                        self.errors.add("output-different", host_name)
            elif host_name == "nic":
                # NIC never gets its console output checked.
                self.logger.debug("host %s has unchecked console output", host_name)
            else:
                self.errors.add("output-unchecked", host_name)


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
    # progression has occured.  For instance:
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
        test_result.errors.add("absent", "baseline")
        return test_result

    base = baseline[test.name]
    baseline_result = TestResult(logger, base, quick)
    if not baseline_result:
        if not test_result.passed:
            test_result.errors.add("missing", "baseline")
        return test_result

    if test_result.passed and baseline_result.passed:
        return test_result

    for host_name in test.host_names:

        if host_name is "nic":
            continue

        if not host_name in test_result.sanitized_console_output:
            continue

        if not host_name in baseline_result.sanitized_console_output:
            test_result.errors.add("baseline-missing", host_name)
            continue

        if not host_name in test_result.diffs:
            if host_name in baseline_result.diffs:
                test_result.errors.add("baseline-failed", host_name)
            continue

        if not host_name in baseline_result.diffs:
            test_result.errors.add("baseline-passed", host_name)
            continue

        baseline_diff, baseline_whitespace = fuzzy_diff(logger,
                                                        "BASELINE/" + test.name + "/" + host_name + ".console.txt",
                                                        baseline_result.sanitized_console_output[host_name],
                                                        "OUTPUT/" + test.name + "/" + host_name + ".console.txt",
                                                        test_result.sanitized_console_output[host_name])
        if baseline_diff:
            if baseline_whitespace:
                test_result.errors.add("baseline-whitespace", host_name)
            else:
                test_result.errors.add("baseline-different", host_name)
            # update the diff to something hopefully closer?
            test_result.diffs[host_name] = baseline_diff
        # else:
        #    test_result.errors.add("baseline-failed", host_name)

    return test_result
