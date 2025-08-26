# Perform post.mortem on a test result, for libreswan.
#
# Copyright (C) 2015-2024 Andrew Cagney
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
import subprocess
import difflib
import weakref
import gzip
import bz2

from fab import logutil
from fab import jsonutil
from fab import printer
from fab import resolution

# Strings used to mark up files; see also runner.py where it marks up
# the file names.  The sanitizer is hardwired to recognize CUT & TUC
# so don't change those strings.

RHS = "<<<<<<<<<<"
LHS = ">>>>>>>>>>"
CUT = LHS + "cut" + LHS
TUC = RHS + "tuc" + RHS
DONE = CUT + " done " + TUC

# Mapping between hosts and their issues and/or issues and their
# hosts.
#
# Two maps are maintained:
#
# - the ISSUE_HOSTS map is indexed by ISSUE, each ISSUE entry then
#   contains a list (set?) of hosts
#
#   This is so that code can easily determine if a specific issue,
#   regardless of the HOST, has occurred.  All the programmatic
#   operators, such as __contains__(), are implemented based on this
#   model.
#
#   XXX: Could probably re-implement issues as an extension of
#   dictionary.
#
# - the HOST_ISSUES map is indexed by HOST, each HOST entry then
#   contains a list (set?) of issues
#
#   This is used to display and dump the issues (__str__(), json()).
#   It seems that the most user friendly format is:
#   host:issue,... host:issue:,...

class Issues:

    ABSENT = "absent"
    SANITIZER_FAILED = "sanitizer-failed"

    ASSERTION = "ASSERTION"
    EXPECTATION = "EXPECTATION"
    CORE = "CORE"
    SEGFAULT = "SEGFAULT"
    GPFAULT = "GPFAULT"
    PRINTF_NULL = "PRINTF_NULL"
    KERNEL = "KERNEL"
    LEAK = "LEAK"
    REFCNT = "REFCNT"

    TIMEOUT = "TIMEOUT"
    EOF = "EOF"
    EXCEPTION = "EXCEPTION"

    ISCNTRL = "iscntrl"

    OUTPUT_MISSING = "output-missing"
    OUTPUT_UNCHECKED = "output-unchecked"
    OUTPUT_TRUNCATED = "output-truncated"
    OUTPUT_WHITESPACE = "output-whitespace"
    OUTPUT_DIFFERENT = "output-different"

    def __init__(self, logger):
        # Structure needs to be JSON friendly.
        self._host_issues = {}
        self._issue_hosts = {}
        self._logger = logger

    # Both __str__() and __json__() dump the table in user friendly
    # format.  That is:
    #
    #     host:issue,...  host:issue,...
    #
    # This is the opposite to what code expects - a dictionary
    # structured issue:host,... .

    def __str__(self):
        s = ""
        for host, errors in sorted(self._host_issues.items()):
            if s:
                s += " "
            if host:
                s += host + ":"
            s += ",".join(sorted(errors))
        return s

    def __json__(self):
        return self._host_issues

    # Programmatic collections like interface.  This is indexed by
    # ISSUE so that it is easy to query Issues to see if an ISSUE
    # occurred on any host.

    def __bool__(self):
        return len(self._issue_hosts) > 0

    def __iter__(self):
        return self._issue_hosts.keys().__iter__()

    def __contains__(self, issue):
        return issue in self._issue_hosts

    def __getitem__(self, issue):
        return self._issue_hosts[issue]

    def add(self, issue, host):
        if not host in self._host_issues:
            self._host_issues[host] = []
        if not issue in self._host_issues[host]:
            self._host_issues[host].append(issue)
        if not issue in self._issue_hosts:
            self._issue_hosts[issue] = []
        if not host in self._issue_hosts[issue]:
            self._issue_hosts[issue].append(host)
        self._logger.debug("host %s has issue %s", host, issue)

    def crashed(self):
        return {Issues.ASSERTION, Issues.EXPECTATION, Issues.CORE, Issues.SEGFAULT, Issues.GPFAULT}.isdisjoint(self);



def _strip(s):
    s = re.sub(rb"[ \t]+", rb"", s)
    s = re.sub(rb"\n+", rb"\n", s)
    s = re.sub(rb"^\n", rb"", s)
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
    diff = list(difflib.diff_bytes(difflib.unified_diff,
                                   l.splitlines(), r.splitlines(),
                                   fromfile=ln.encode(), tofile=rn.encode(),
                                   lineterm=rb""))
    logger.debug("_diff: %s", diff)
    if not diff:
        # Always return a list.
        return []
    return diff


def _sanitize_output(logger, raw_path, test):
    # Run the sanitizer found next to the test_sanitize_directory.
    command = [
        test.testing_directory("utils", "sanitizer.sh"),
        raw_path,
        test.testing_directory("pluto", test.name)
    ]
    logger.debug("sanitize command: %s", command)
    # Note: It is faster to have "sanitize.sh" read the file on disk
    # then try to feed it (via a pipe) the copy of the file in memory.
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    logger.debug("sanitized output:\n%s", stdout)
    if process.returncode or stderr:
        # any hint of an error
        logger.error("sanitize command '%s' failed; exit code %s; stderr: %s",
                     command, process.returncode, stderr.decode('utf-8'))
        return None
    return stdout


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
        return self.resolution in [resolution.PASSED, resolution.FAILED, resolution.UNRESOLVED]

    def __init__(self, logger, test, quick, output_directory=None):

        # Set things up for passed
        self.logger = logger
        self.test = test
        self.resolution = resolution.Resolution()
        self.issues = Issues(self.logger)
        self.diff_output = {}
        self.sanitized_output = {}
        self._file_contents_cache = {}
        self.output_directory = output_directory or test.output_directory
        # times
        self._start_time = None
        self._stop_time = None
        self._total_time = None
        self._boot_time = None
        self._test_time = None
        self._json = None

        # If there is no OUTPUT directory the result is UNTESTED -
        # presence of the OUTPUT is a clear indicator that some
        # attempt was made to run the test.
        if not os.path.exists(self.output_directory):
            self.resolution.untested()
            self.logger.debug("output directory missing: %s", self.output_directory)
            return

        # Start out assuming that it passed and then prove otherwise.

        self.resolution.passed()

        # check the log files for problems

        for guest in test.guests:
            pluto_log_filename = guest.host.name + ".pluto.log"
            if self._grub(pluto_log_filename, r"ASSERTION FAILED"):
                self.issues.add(Issues.ASSERTION, guest.host.name)
                self.resolution.failed()
            if self._grub(pluto_log_filename, r"EXPECTATION FAILED"):
                self.issues.add(Issues.EXPECTATION, guest.host.name)
                self.resolution.failed()
            if self._grub(pluto_log_filename, r"\(null\)"):
                self.issues.add(Issues.PRINTF_NULL, guest.host.name)
                self.resolution.failed()
            if self._grub(pluto_log_filename, r"[^ -~\n]"):
                # This won't detect a \n embedded in the middle of a
                # log line.
                self.issues.add(Issues.ISCNTRL, guest.host.name)
                self.resolution.failed()
            if self._grub(pluto_log_filename, r"leak detective found [0-9]+ leaks"):
                self.issues.add(Issues.LEAK, guest.host.name)
                self.resolution.failed()

        # Generate tpple lists of what to sanitize and what to
        # verify.
        #
        # Always sanitize both console outputs (merged and split) so
        # that both are available.
        #
        # Only verify one of the merged console.txt and the split
        # console.txt (but not both).

        verify = []
        if os.path.exists(os.path.join(test.directory, "all.console.txt")):
            verify.append("all")
        else:
            for guest in test.guests:
                verify.append(guest.host.name)

        sanitize = []
        for guest in test.guests:
            sanitize.append(guest.host.name)
        if os.path.exists(os.path.join(test.directory, "all.sh")) \
        or os.path.exists(os.path.join(test.directory, "all.console.txt")):
            sanitize.append("all")

        # Check the raw console output for problems and that it
        # matches expected output.

        for host_name in verify:

            raw_output_filename = host_name + ".console.verbose.txt"

            # Check that the host's raw output is present.
            #
            # If there is no output at all then the test crashed badly
            # (for instance, while trying to boot domains).
            #
            # Since things really screwed up, mark the test as
            # UNRESOLVED and give up.

            if self._grub(raw_output_filename) is None:
                self.issues.add(Issues.OUTPUT_MISSING, host_name)
                self.resolution.unresolved()
                # With no raw console output, there's little point in
                # trying validating it.  Skip remaining tests for this
                # host.
                continue

            # Check the host's raw output for signs of a crash.
            #
            # Need to repeat EXPECTATION and ASSERTION.  It might be a
            # command line utility that barfs.

            self.logger.debug("checking %s for signs of a crash", raw_output_filename)
            if self._grub(raw_output_filename, r"[\r\n]CORE FOUND"):
                self.issues.add(Issues.CORE, host_name)
                self.resolution.failed()
            if self._grub(raw_output_filename, r"SEGFAULT"):
                self.issues.add(Issues.SEGFAULT, host_name)
                self.resolution.failed()
            if self._grub(raw_output_filename, r"GPFAULT"):
                self.issues.add(Issues.GPFAULT, host_name)
                self.resolution.failed()
            if self._grub(raw_output_filename, r"ASSERTION FAILED"):
                self.issues.add(Issues.ASSERTION, host_name)
                self.resolution.failed()
            if self._grub(raw_output_filename, r"EXPECTATION FAILED"):
                self.issues.add(Issues.EXPECTATION, host_name)
                self.resolution.failed()
            if self._grub(raw_output_filename, r"\(null\)"):
                self.issues.add(Issues.PRINTF_NULL, host_name)
                self.resolution.failed()
            if self._grub(raw_output_filename, r"FAIL: reference counts"):
                self.issues.add(Issues.REFCNT, guest.host.name)
                self.resolution.failed()

            # Check that the host's raw output is complete.
            #
            # The last thing written to the file should be the DONE
            # marker.  If not then it could be: a timeout; an
            # exception; or the test is still in-progress.

            logger.debug("host %s checking if raw console output is complete");

            if self._grub(raw_output_filename, LHS + " " + Issues.TIMEOUT):
                # One of the test scripts hung; all the
                self.issues.add(Issues.TIMEOUT, host_name)
                self.resolution.failed()

            if self._grub(raw_output_filename, LHS + " " + Issues.EOF):
                # One of the test scripts hung; all the
                self.issues.add(Issues.EOF, host_name)
                self.resolution.unresolved()

            if self._grub(raw_output_filename, LHS + " " + Issues.EXCEPTION):
                # One of the test scripts hung; all the
                self.issues.add(Issues.EXCEPTION, host_name)
                self.resolution.unresolved()

            if self._grub(raw_output_filename, DONE) is None:
                self.issues.add(Issues.OUTPUT_TRUNCATED, host_name)
                self.resolution.unresolved()

        # Sanitize what ever output there is.
        #
        # Even when the output is seemingly truncated this is useful.
        # Sanitize both merged and individual files so there is a
        # choice for what to look at.

        for host_name in sanitize:

            sanitized_filename = host_name + ".console.txt"
            sanitized_path = os.path.join(self.output_directory, sanitized_filename)
            raw_filename = host_name + ".console.verbose.txt"
            raw_path = os.path.join(self.output_directory, raw_filename)

            if not os.path.exists(raw_path):
                self.logger.debug("skipping sanitize as no raw output: %s", raw_path)
                continue

            self.logger.debug("sanitize console output '%s'", sanitized_path)
            sanitized_output = None
            if quick:
                sanitized_output = self._file_contents(sanitized_path)
            if sanitized_output is None:
                sanitized_output = _sanitize_output(self.logger,
                                                    os.path.join(self.output_directory, raw_filename),
                                                    test)
            if sanitized_output is None:
                self.issues.add(Issues.SANITIZER_FAILED, host_name)
                self.resolution.unresolved()
                continue
            self.sanitized_output[host_name] = sanitized_output

        # now verify just one of the sanitized results

        for host_name in verify:
            sanitized_filename = host_name + ".console.txt"
            if host_name not in self.sanitized_output:
                continue
            sanitized_output = self.sanitized_output[host_name]

            self.logger.debug("checking %s for issues", sanitized_filename)
            if self._grep(sanitized_output, r"\(null\)"):
                self.issues.add(Issues.PRINTF_NULL, host_name)
                self.resolution.failed()
            if self._grep(sanitized_output, r"[^ -~\r\n\t]"):
                # Console contains \r\n; this won't detect \n embedded
                # in the middle of a log line.  Audit emits embedded
                # escapes!
                self.issues.add(Issues.ISCNTRL, host_name)
                self.resolution.failed()
            if self._grep(sanitized_output, r"\[ *\d+\.\d+\] Call Trace:"):
                # the sanitizer strips out the bogus backtrace "failed
                # to disable LRO"; hence checking the sanitized output
                self.issues.add(Issues.KERNEL, host_name)
                self.resolution.failed()

            expected_output_path = test.testing_directory("pluto", test.name,
                                                          host_name + ".console.txt")
            self.logger.debug("comparing %s against known-good output '%s'",
                              sanitized_filename, expected_output_path)

            expected_output = self._file_contents(expected_output_path)
            if expected_output is None:
                self.issues.add(Issues.OUTPUT_UNCHECKED, host_name)
                self.resolution.failed()
                continue

            diff_output = None
            diff_filename = host_name + ".console.diff"

            if quick:
                # Try to load the existing diff file.  Like _diff()
                # save a list of lines.
                diff_output = self._grub(diff_filename)
                if diff_output is not None:
                    diff_output = diff_output.splitlines()
            if diff_output is None:
                # use brute force
                diff_output = _diff(self.logger,
                                    "MAIN/" + test.directory + "/" + host_name + ".console.txt",
                                    expected_output,
                                    "OUTPUT/" + test.directory + "/" + host_name + ".console.txt",
                                    sanitized_output)

            # always add entry so that save() knows what to write
            self.diff_output[host_name] = diff_output

            if Issues.OUTPUT_TRUNCATED in self.issues:
                self.logger.debug("skipping diff as truncated")
            elif diff_output:
                whitespace = _whitespace(expected_output, sanitized_output)
                self.resolution.failed()
                if whitespace:
                    self.issues.add(Issues.OUTPUT_WHITESPACE, host_name)
                else:
                    self.issues.add(Issues.OUTPUT_DIFFERENT, host_name)

    def save(self, output_directory=None):
        output_directory = output_directory or self.output_directory
        if not os.path.exists(self.output_directory):
            self.logger.debug("output directory missing: %s", output_directory)
            return
        # write the sanitized console output
        for host_name, sanitized_output in self.sanitized_output.items():
            sanitized_filename = host_name + ".console.txt"
            sanitized_path = os.path.join(output_directory, sanitized_filename)
            self.logger.debug("writing sanitized output file: %s", sanitized_path)
            with open(sanitized_path, "wb") as f:
                f.write(sanitized_output)
        # write the diffs
        for host_name, diff_output in self.diff_output.items():
            diff_filename = host_name + ".console.diff"
            diff_path = os.path.join(output_directory, diff_filename)
            self.logger.debug("writing diff file %s", diff_path)
            with open(diff_path, "wb") as f:
                if diff_output:
                    for line in diff_output:
                        f.write(line)
                        f.write(b"\n")

        # Convert the result into json, and save it
        json = self.json()
        result_file = os.path.join(output_directory, "result.json")
        self.logger.debug("writing %s to %s", json, result_file)
        with open(result_file, "w") as output:
            jsonutil.dump(json, output)
            output.write("\n")

        # Emit enough JSON to fool scripts like
        # pluto-testlist-scan.sh.
        #
        # A test that timed-out or crashed, isn't considered
        # resolved so the file isn't created.
        #
        # XXX: this should go away.
        result_file = os.path.join(output_directory, "RESULT")
        if self.resolution.isresolved():
            RESULT = {
                jsonutil.result.testname: self.test.name,
                jsonutil.result.expect: self.test.status,
                jsonutil.result.result: self.__str__(),
                jsonutil.result.issues: self.issues,
                jsonutil.result.hosts: self.test.guests,
            }
            self.logger.debug("writing %s %s", json, result_file)
            with open(result_file, "w") as output:
                jsonutil.dump(RESULT, output)
                output.write("\n")

    def _file_contents(self, path):
        # Find/load the file, and uncompress when needed.
        if not path in self._file_contents_cache:
            self.logger.debug("loading contents of '%s'", path)
            self._file_contents_cache[path] = None
            for suffix, open_op in [("", open), (".gz", gzip.open), (".bz2", bz2.open),]:
                zippath = path + suffix
                if os.path.isfile(zippath):
                    self.logger.debug("loading '%s' into cache", zippath)
                    with open_op(path, "rb") as f:
                        self._file_contents_cache[path] = f.read()
                        self.logger.debug("loaded contents of '%s'", zippath)
                        break
        return self._file_contents_cache[path]

    def _grub(self, filename, regex=None, cast=None):
        """Grub around FILENAME to find regex"""
        self.logger.debug("grubbing '%s' for '%s'", filename, regex)
        path = os.path.join(self.output_directory, filename)
        contents = self._file_contents(path)
        if regex is None:
            return contents # could be None
        matched = self._grep(contents, regex)
        if matched is None:
            return None
        if cast:
            # caller is matching valid utf-8, decode and cast
            result = cast(matched.decode('utf-8'))
        else:
            # caller isn't interested in what matched, return success
            result = True
        self.logger.debug("grep() result %s", result)
        return result

    def _grep(self, contents, regex):
        if contents is None:
            return None
        self.logger.debug("grep() content type is %s", type(contents))
        # convert utf-8 regex to bytes
        self.logger.debug("grep() encoding regex type %s to raw bytes using utf-8", type(regex))
        byte_regex = regex.encode()
        match = re.search(byte_regex, contents, re.MULTILINE)
        if not match:
            return None
        group = match.group(len(match.groups()))
        self.logger.debug("grep() '%s' matched '%s'", regex, group)
        return group	# truthy

    def start_time(self):
        if not self._start_time:
            # starting debug log at 2018-08-15 13:00:12.275358
            self._start_time = self._grub("debug.log",
                                         r"starting debug log at (.*)$",
                                         cast=jsonutil.ptime)
        return self._start_time

    def stop_time(self):
        if not self._stop_time:
            # ending debug log at 2018-08-15 13:01:31.602533
            self._stop_time = self._grub("debug.log",
                                         r"ending debug log at (.*)$",
                                         cast=jsonutil.ptime)
        return self._stop_time

    def total_time(self):
        if not self._total_time:
            # stop testing basic-pluto-01 (test 2 of 756) after 79.3 seconds
            self._total_time = self._grub("debug.log",
                                          r": stop testing .* after ([0-9].*) second",
                                          cast=float)
        return self._total_time

    def boot_time(self):
        if not self._boot_time:
            # stop booting domains after 56.9 seconds
            self._boot_time = self._grub("debug.log",
                                         r": stop booting domains after ([0-9].*) second",
                                         cast=float)
        return self._boot_time

    def test_time(self):
        if not self._test_time:
            # stop running commands after 56.9 seconds
            self._test_time = self._grub("debug.log",
                                         r": stop running commands after ([0-9].*) second",
                                         cast=float)
        return self._test_time

    def json(self):
        if not self._json:
            # Convert the result into json, and save it
            result_to_json = printer.Print(printer.Print.TEST_NAME,
                                           printer.Print.TEST_KIND,
                                           printer.Print.TEST_STATUS,
                                           printer.Print.TEST_GUEST_PLATFORMS,
                                           printer.Print.TEST_HOST_NAMES,
                                           printer.Print.START_TIME,
                                           printer.Print.STOP_TIME,
                                           printer.Print.RESULT,
                                           printer.Print.ISSUES,
                                           printer.Print.TOTAL_TIME,
                                           printer.Print.BOOT_TIME,
                                           printer.Print.TEST_TIME)
            json_builder = printer.JsonBuilder()
            printer.build_result(self.logger, self, result_to_json, json_builder)
            self._json = json_builder.json()
        return self._json


# XXX: given that most of args are passed in unchagned, this should
# change to some type of result factory.

def mortem(test, args, logger, output_directory=None, quick=False):

    return TestResult(logger, test, quick,
                      output_directory=output_directory)
