# Perform post.mortem on a test result, for libreswan.
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
import subprocess
import difflib
from fab import utils

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


# The TestResult objects are almost, but not quite, an enum. It
# carries around additional result details.

class TestResult:

    def __init__(self, test, errors={}, diffs={}):
        self.errors = errors
        self.diffs = diffs
        self.test = test
        test.logger.debug("%s: %s", test.name, self)

    def __str__(self):
        if self.errors:
            return "%s %s" % (self.value, self.errors)
        else:
            return self.value

class TestIncomplete(TestResult):
    value = "incomplete"
    passed = None
class TestFailed(TestResult):
    value = "failed"
    passed = False
class TestPassed(TestResult):
    value = "passed"
    passed = True



# Dictionary to accumulate errors from a test run.

class Errors:

    def __init__(self, logger):
        self.errors = {}
        self.logger = logger

    # this formatting is subject to infinite feedback.
    def __str__(self):
        s = None
        for who in sorted(self.errors):
            if s:
                s += " "
            else:
                s = ""
            s += who + ":"
            s += ",".join(sorted(self.errors[who]))
        return s

    # So, like a real collection, can easily test if non-empty.
    def __bool__(self):
        return len(self.errors) > 0

    # Iterate over the actual errors, not who had them.
    def __iter__(self):
        values = set()
        for errors in self.errors.values():
            values |= errors
        return values.__iter__()

    def add(self, what, who="all"):
        if not who in self.errors:
            self.errors[who] = set()
        self.errors[who].add(what)
        self.logger.debug("domain %s has %s", who, what)

    def search(self, regex, line, what, who):
        if re.search(regex, line):
            self.add(what, who)

    def grep(self, regex, filename, what, who):
        command = ['grep', '-e', regex, filename]
        process = subprocess.Popen(command, stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            self.add(what, who)


def strip_space(s):
    s = re.sub(r"[ \t]+", r"", s)
    return s

def strip_blank_line(s):
    s = re.sub(r"\n+", r"\n", s)
    s = re.sub(r"^\n", r"", s)
    return s

# Compare two strings; hack to mimic "diff -N -w -B"?
def fuzzy_diff(logger, ln, l, rn, r,
               strip_spaces=False,
               strip_blank_lines=False):
    if l == r:
        # fast path
        logger.debug("fuzzy_diff fast match")
        return "", "identical"
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
        return diff, "same"
    # see if the problem was just white space
    if not strip_spaces and not strip_blank_lines:
        l = strip_blank_line(strip_space(l))
        r = strip_blank_line(strip_space(r))
        if l == r:
            return diff, "whitespace"
    return diff, "different"


def sanitize_output(logger, raw_file, test_directory):
    command = [ utils.relpath("sanitizer.sh"), raw_file, test_directory ]
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


def mortem(test, args, baseline=None, skip_diff=False, skip_sanitize=False,
           output_directory=None,
           update=False, update_diff=False, update_sanitize=False):

    update_diff = update or update_diff
    update_sanitize = update or update_sanitize

    strip_spaces = args.ignore_all_spaces
    strip_blank_lines = args.ignore_blank_lines

    output_directory = output_directory or test.output_directory
    if not os.path.exists(output_directory):
        test.logger.debug("output directory missing: %s", output_directory)
        return None

    errors = Errors(test.logger)
    diffs = {}

    # Check the pluto logs for markers indicating that there was a
    # crash or other unexpected behaviour.
    for domain in test.domain_names():
        pluto_log = os.path.join(output_directory, domain + ".pluto.log")
        test.logger.debug("checking '%s' for markers", pluto_log)
        if os.path.exists(pluto_log):
            errors.grep("ASSERTION FAILED", pluto_log, "ASSERTION", domain)
            errors.grep("EXPECTATION FAILED", pluto_log, "EXPECTATION", domain)

    # Check the console output for problems and that it matches
    # expected output.
    finished = True
    for domain in test.domain_names():

        # There should always be raw console output from all
        # domains.  If there isn't then there's a big problem and
        # little point with continuing checks for this domain.

        raw_console_file = os.path.join(output_directory,
                                        domain + ".console.verbose.txt")
        test.logger.debug("domain %s raw console output '%s'", domain, raw_console_file)
        if not os.path.exists(raw_console_file):
            errors.add("missing", domain)
            finished = False
            continue

        test.logger.debug("domain %s loading raw console output", domain)
        with open(raw_console_file) as f:
            raw_console_output = f.read()

        test.logger.debug("domain %s checking raw console output for signs of a crash", domain)
        errors.search(r"[\r\n]CORE FOUND", raw_console_output, "CORE", domain)
        errors.search(r"SEGFAULT", raw_console_output, "SEGFAULT", domain)
        errors.search(r"GPFAULT", raw_console_output, "GPFAULT", domain)

        # Truncated output won't match expected output so skip any
        # comparisons.
        test.logger.debug("domain %s checking if raw console output was truncated", domain)
        if not "# : ==== end ====" in raw_console_output:
            errors.add("truncated", domain)
            finished = False
            continue

        sanitized_console_file = os.path.join(output_directory,
                                              domain + ".console.txt")
        test.logger.debug("domain %s sanitize console output '%s'", domain, sanitized_console_file)
        sanitized_console_output = None
        if skip_sanitize:
            sanitized_console_output = load_output(test.logger, sanitized_console_file)
        if not sanitized_console_output:
            sanitized_console_output = sanitize_output(test.logger, raw_console_file, test.directory)
        if not sanitized_console_output:
            errors.add("sanitizer-failed", domain)
            continue
        if update_sanitize:
            test.logger.debug("domain %s updating sanitized output file: %s", domain, sanitized_console_file)
            with open(sanitized_console_file, "w") as f:
                f.write(sanitized_console_output)

        expected_output_file = os.path.join(test.directory, domain + ".console.txt")
        test.logger.debug("domain %s comparing against known-good output '%s'", domain, expected_output_file)
        if os.path.exists(expected_output_file):
            with open(expected_output_file) as f:
                expected_output = f.read()
            console_diff_file = os.path.join(output_directory, domain + ".console.diff")
            console_diff = None
            different = "different"
            if skip_diff:
                console_diff = load_output(test.logger, console_diff_file)
                # be consistent with fuzzy_diff which returns a list
                # of lines.
                if console_diff:
                    console_diff = console_diff.splitlines()
            if not console_diff:
                console_diff, different = fuzzy_diff(test.logger,
                                                     domain + ".console.txt", expected_output,
                                                     "OUTPUT/" + domain + ".console.txt", sanitized_console_output,
                                                     strip_spaces=strip_spaces,
                                                     strip_blank_lines=strip_blank_lines)
            if update_diff:
                test.logger.debug("domain %s updating diff file %s", domain, console_diff_file)
                with open(console_diff_file, "w") as f:
                    for line in console_diff:
                        f.write(line)
                        f.write("\n")
            if not console_diff:
                test.logger.debug("%s console and expected output match", domain)
                continue
            errors.add(different, domain)
            diffs[domain] = console_diff
        elif domain == "nic":
            # NIC never gets its console output checked.
            test.logger.debug("domain %s has unchecked console output", domain)
        else:
            errors.add("unchecked", domain)

        # Perhaps the baseline gives a better diff?
        if not baseline:
            continue

        if not test.name in baseline:
            errors.add("baseline-absent")
            continue
        base = baseline[test.name]

        raw_baseline_file = os.path.join(base.output_directory, domain + ".console.verbose.txt")
        test.logger.debug("domain %s raw baseline output: %s", raw_baseline_file)
        sanitized_baseline_file = os.path.join(base.output_directory, domain + ".console.txt")
        test.logger.debug("domain %s sanitzed baseline output: %s", raw_baseline_file)

        if not os.path.exists(raw_baseline_file):
            errors.add("baseline-missing", domain)
            continue

        sanitized_baseline_output = None
        if skip_sanitize:
            sanitized_baseline_output = load_output(sanitized_baseline_file)
        if not sanitized_baseline_output:
            sanitized_baseline_output = sanitize_output(test.logger, raw_baseline_file, test.directory)
        if not sanitized_baseline_output:
            errors.add("baseline-sanitizer-failed", domain)
            continue
        # Update?

        baseline_diff, different = fuzzy_diff(test.logger,
                                              "BASELINE/" + domain + ".console.txt", sanitized_baseline_output,
                                              "OUTPUT/" + domain + ".console.txt", sanitized_console_output,
                                              strip_spaces=strip_spaces,
                                              strip_blank_lines=strip_blank_lines)
        if baseline_diff:
            errors.add("baseline-" + different, domain)
            diffs[domain] = baseline_diff

        # end-loop

    # The final result
    if not finished:
        return TestIncomplete(test, errors=errors, diffs=diffs)
    elif errors:
        return TestFailed(test, errors=errors, diffs=diffs)
    else:
        return TestPassed(test)
