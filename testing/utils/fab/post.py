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
from collections import defaultdict

from fab import utilsdir

def add_arguments(parser):
    group = parser.add_argument_group("Postmortem arguments",
                                      "Options for controlling the analysis of the test results")

    # If it gets decided that these arguments should be enabled by
    # default then the following can be used to make them like flags:
    # nargs="?", type=argutil.boolean, const="true", default="false",
    group.add_argument("--ignore-all-spaces", "-w",
                       action="store_true",
                       help="ignore (strip out) all white space")
    group.add_argument("--ignore-blank-lines", "-B",
                       action="store_true",
                       help="ignore (strip out) blank lines")

def log_arguments(logger, args):
    logger.info("Postmortem arguments")
    logger.info("  ignore-all-spaces: %s", args.ignore_all_spaces)
    logger.info("  ignore-blank-lines: %s", args.ignore_blank_lines)


# Dictionary to accumulate all the errors for each host from an
# individual test.

class Errors:

    def __init__(self, logger):
        self.errors = defaultdict(set)
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

    # So, like a real collection, can easily test if non-empty.
    def __bool__(self):
        return len(self.errors) > 0

    # Iterate over the actual errors, not who had them.  XXX: there's
    # not much consistency between __iter__(), items(), __contains__()
    # and __getitem__().  On the other hand, a hashmap iter isn't
    # consistent either.
    def __iter__(self):
        values = set()
        for errors in self.errors.values():
            values |= errors
        return values.__iter__()

    def __contains__(self, item):
        return item in self.errors

    def __getitem__(self, item):
        return self.errors[item]

    def items(self):
        return self.errors.items()

    def add(self, error, host=None):
        self.errors[host].add(error)
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
        process = subprocess.Popen(command, stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            self.add(error, host)
            return True
        else:
            return False

def strip_space(s):
    s = re.sub(r"[ \t]+", r"", s)
    return s

def strip_blank_line(s):
    s = re.sub(r"\n+", r"\n", s)
    s = re.sub(r"^\n", r"", s)
    return s

# Compare two strings; hack to mimic "diff -N -w -B"?
# Returns:
#    [], None
#    [diff..], True # if white space only
#    [diff...], False
def fuzzy_diff(logger, ln, l, rn, r,
               strip_spaces=False,
               strip_blank_lines=False):
    if l == r:
        # fast path
        logger.debug("fuzzy_diff fast match")
        return [], None
    # Could be more efficient
    if strip_spaces:
        l = strip_space(l)
        r = strip_space(r)
    if strip_blank_lines:
        l = strip_blank_line(l)
        r = strip_blank_line(r)
    # compare
    diff = list(difflib.unified_diff(l.splitlines(), r.splitlines(),
                                     fromfile=ln, tofile=rn,
                                     lineterm=""))
    logger.debug("fuzzy_diff: %s", diff)
    if not diff:
        return [], None
    # see if the problem was just white space; hack
    if not strip_spaces and not strip_blank_lines:
        l = strip_blank_line(strip_space(l))
        r = strip_blank_line(strip_space(r))
        if l == r:
            return diff, True
    return diff, False


def sanitize_output(logger, raw_file, test_directory):
    command = [ utilsdir.relpath("sanitizer.sh"), raw_file, test_directory ]
    logger.debug("sanitize command: %s", command)
    # Note: It is faster to re-read the file than read the
    # pre-loaded raw console output.
    process = subprocess.Popen(command, stdout=subprocess.PIPE)
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
            # Sounds good doesn't mean anything.  It might be because
            # the test aborted, but it could also be because the test
            # is still in-progress.
            return "incomplete"
        else:
            return "untested"

    def __bool__(self):
        # Things started - passed is valid
        return self.finished is not None

    def __init__(self, test, skip_diff, skip_sanitize,
                 output_directory=None, test_finished=None,
                 update_diff=False, update_sanitize=False,
                 strip_spaces=False, strip_blank_lines=False):

        self.test = test
        self.passed = None
        self.finished = None
        self.errors = Errors(test.logger)
        self.diffs = {}
        self.sanitized_console_output = {}

        output_directory = output_directory or test.output_directory

        # An OUTPUT directory is a clear indicator that something was
        # started.
        if not os.path.exists(output_directory):
            test.logger.debug("output directory missing: %s", output_directory)
            return
        if test_finished is None:
            # Use RESULT as a proxy for a test finishing.  It isn't
            # 100% reliable since an in-progress test looks list like
            # an aborted test.
            self.finished = os.path.isfile(test.result_file(output_directory));
        else:
            self.finished = test_finished;

        # Be optimistic; passed is only really valid when finished is
        # true.
        self.passed = True

        # crash or other unexpected behaviour.
        for host_name in test.host_names:
            pluto_log = os.path.join(output_directory, host_name + ".pluto.log")
            if os.path.exists(pluto_log):
                test.logger.debug("checking '%s' for errors", pluto_log)
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
            test.logger.debug("host %s raw console output '%s'", host_name, raw_console_file)
            if not os.path.exists(raw_console_file):
                self.errors.add("output-missing", host_name)
                self.passed = False
                continue

            test.logger.debug("host %s loading raw console output", host_name)
            with open(raw_console_file) as f:
                raw_console_output = f.read()

            test.logger.debug("host %s checking raw console output for signs of a crash", host_name)
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

            #test.logger.debug("host %s checking if raw console output was incomplete", host_name)
            #if not "# : ==== end ====" in raw_console_output:
            #    self.errors.add("output-incomplete", host_name)
            #    self.passed = False
            #    continue

            sanitized_console_file = os.path.join(output_directory,
                                                  host_name + ".console.txt")
            test.logger.debug("host %s sanitize console output '%s'", host_name, sanitized_console_file)
            sanitized_console_output = None
            if skip_sanitize:
                sanitized_console_output = load_output(test.logger, sanitized_console_file)
            if not sanitized_console_output:
                sanitized_console_output = sanitize_output(test.logger, raw_console_file, test.sanitize_directory)
            if not sanitized_console_output:
                self.errors.add("sanitizer-failed", host_name)
                continue
            if update_sanitize:
                test.logger.debug("host %s updating sanitized output file: %s", host_name, sanitized_console_file)
                with open(sanitized_console_file, "w") as f:
                    f.write(sanitized_console_output)

            self.sanitized_console_output[host_name] = sanitized_console_output

            expected_sanitized_console_output_file = os.path.join(test.sanitize_directory, host_name + ".console.txt")
            test.logger.debug("host %s comparing against known-good output '%s'", host_name, expected_sanitized_console_output_file)
            if os.path.exists(expected_sanitized_console_output_file):

                diff, whitespace = [], None

                sanitized_console_diff_file = os.path.join(output_directory, host_name + ".console.diff")
                if skip_diff:
                    sanitized_console_diff = load_output(test.logger, sanitized_console_diff_file)
                    # be consistent with fuzzy_diff which returns a list
                    # of lines.
                    if sanitized_console_diff:
                        diff, whitespace = sanitized_console_diff.splitlines(), False
                if not diff:
                    with open(expected_sanitized_console_output_file) as f:
                        expected_sanitized_console_output = f.read()
                    diff, whitespace = fuzzy_diff(test.logger,
                                                  "MASTER/" + test.name + "/" + host_name + ".console.txt",
                                                  expected_sanitized_console_output,
                                                  "OUTPUT/" + test.name + "/" + host_name + ".console.txt",
                                                  sanitized_console_output,
                                                  strip_spaces=strip_spaces,
                                                  strip_blank_lines=strip_blank_lines)
                if update_diff:
                    test.logger.debug("host %s updating diff file %s", host_name, sanitized_console_diff_file)
                    with open(sanitized_console_diff_file, "w") as f:
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
                test.logger.debug("host %s has unchecked console output", host_name)
            else:
                self.errors.add("output-unchecked", host_name)


# XXX: given that most of args are passed in unchagned, this should
# change to some type of object.

def mortem(test, args, baseline=None, skip_diff=False, skip_sanitize=False,
           output_directory=None, test_finished=None,
           update=False, update_diff=False, update_sanitize=False):

    update_diff = update or update_diff
    update_sanitize = update or update_sanitize

    strip_spaces = args.ignore_all_spaces
    strip_blank_lines = args.ignore_blank_lines

    test_result = TestResult(test, skip_diff, skip_sanitize,
                             output_directory, test_finished=test_finished,
                             update_diff=update_diff,
                             update_sanitize=update_sanitize,
                             strip_spaces=strip_spaces,
                             strip_blank_lines=strip_blank_lines)

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
    baseline_result = TestResult(base, skip_diff, skip_sanitize,
                                 strip_spaces=strip_spaces,
                                 strip_blank_lines=strip_blank_lines)
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

        baseline_diff, baseline_whitespace = fuzzy_diff(test.logger,
                                                        "BASELINE/" + test.name + "/" + host_name + ".console.txt",
                                                        baseline_result.sanitized_console_output[host_name],
                                                        "OUTPUT/" + test.name + "/" + host_name + ".console.txt",
                                                        test_result.sanitized_console_output[host_name],
                                                        strip_spaces=strip_spaces,
                                                        strip_blank_lines=strip_blank_lines)
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
