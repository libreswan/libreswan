# Print a test result summary gathered by scanning the OUTPUT.
#
# Copyright (C) 2015-2017 Andrew Cagney <cagney@gnu.org>
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

import argparse
import sys
import os
import re
from enum import Enum

from fab import testsuite
from fab import logutil
from fab import post
from fab import skip
from fab import ignore
from fab import argutil
from fab import jsonutil

class Print(argutil.List):
    # tests
    TEST_DIRECTORY = "test-directory"
    TEST_GUEST_NAMES = "test-guest-names"
    TEST_HOST_NAMES = "test-host-names"
    TEST_GUEST_PLATFORMS = "test-guest-platforms"
    TEST_PLATFORMS = "test-platforms"
    TEST_KIND = "test-kind"
    TEST_NAME = "test-name"
    TEST_COMMANDS = "test-commands"
    TEST_STATUS = "test-status"
    # results
    START_TIME = "start-time"
    STOP_TIME = "stop-time"
    TOTAL_TIME = "total-time"
    BOOT_TIME = "boot-time"
    TEST_TIME = "test-time"
    DIFFS = "diffs"
    ISSUES = "issues"
    OUTPUT_DIRECTORY = "output-directory"
    PATH = "path"
    RESULT = "result"
    SAVED_OUTPUT_DIRECTORY = "saved-output-directory"
    TESTING_DIRECTORY = "testing-directory"


class JsonBuilder:
    def __init__(self, stream=None):
        self.stream = stream
        self.table = {}
    def prefix(self, key, value):
        self.add(str(key), value)
    def add(self, *keyval, string=None):
        keys = [key.replace("-","_") for key in keyval[0:-1]]
        value = keyval[-1]
        # Only suppress non-existent values.
        if value is None:
            return
        table = self.table
        for key in keys[0:-1]:
            key = key.replace("-","_")
            if not key in table:
                table[key] = {}
            table = table[key]
        table[keys[-1]] = value
    def json(self):
        return self.table
    def flush(self):
        if self.stream:
            jsonutil.dump(self.table, self.stream)
            self.stream.write("\n")
            self.stream.flush()


class TextBuilder:
    def __init__(self, stream=sys.stdout):
        self.eol = False
        self.sep = ""
        self.stream = stream
    def prefix(self, key, value):
        self.stream.write(value)
        self.eol = True
    def add(self, *keyval, string=lambda s, sep: s and sep + str(s) or ""):
        # default is to print value as a string when it is "not
        # false".
        keys = keyval[0:-1]
        value = keyval[-1]
        self.stream.write(string(value, self.sep))
        self.sep = " "
        self.eol = True
    def flush(self):
        if self.eol:
            self.stream.write("\n")
        self.stream.flush()
        self.sep = ""
        self.eol = False


def build_result(logger, result, what_to_print, b):

    # Print the test's name/path

    for p in what_to_print:
        match p:
            case Print.PATH:
                # When the path given on the command line explicitly
                # specifies a test's output directory (found in
                # RESULT.TEST.SAVED_OUTPUT_DIRECTORY), print that; otherwise
                # print the path to the test's directory.
                b.add(p, (result.test.saved_output_directory
                          and result.test.saved_output_directory
                          or result.test.directory))
            case Print.TEST_DIRECTORY:
                b.add(p, result.test.directory)
            case Print.TEST_STATUS:
                b.add(p, result.test.status)
            case Print.TEST_GUEST_NAMES:
                b.add(p, [guest.name for guest in result.test.guests],
                      string=lambda names, sep: sep + ",".join(names))
            case Print.TEST_HOST_NAMES:
                b.add(p, [guest.host.name for guest in result.test.guests],
                      string=lambda names, sep: sep + ",".join(names))
            case Print.TEST_GUEST_PLATFORMS:
                b.add(p, [guest.platform for guest in result.test.guests],
                      string=lambda names, sep: sep + ",".join(names))
            case Print.TEST_PLATFORMS:
                b.add(p, result.test.platforms,
                      string=lambda platforms, sep: sep + ",".join(platforms))
            case Print.TEST_KIND:
                b.add(p, result.test.kind)
            case Print.TEST_NAME:
                b.add(p, result.test.name)
            case Print.OUTPUT_DIRECTORY:
                b.add(p, result.test.output_directory)
            case Print.RESULT:
                b.add(p, result)
            case Print.ISSUES:
                b.add(p, result.issues)
            case Print.TESTING_DIRECTORY:
                b.add(p, result.test.testing_directory())
            case Print.SAVED_OUTPUT_DIRECTORY:
                b.add(p, result.test.saved_output_directory)
            case Print.TEST_COMMANDS:
                b.add(p, result.test.commands)
            case Print.START_TIME:
                b.add(p, result.start_time())
            case Print.STOP_TIME:
                b.add(p, result.stop_time())
            case Print.TOTAL_TIME:
                b.add(p, result.total_time())
            case Print.BOOT_TIME:
                b.add(p, result.boot_time())
            case Print.TEST_TIME:
                b.add(p, result.test_time())
            case Print.DIFFS:
                continue # see below
            case _:
                raise Exception("unhandled print option %s" % p)

    if Print.DIFFS in what_to_print:
        for guest_name, diff_output in result.diff_output.items():
            if diff_output: # could be blank
                b.add(Print.DIFFS, guest_name, diff_output,
                      string=(lambda diff, sep: diff
                              and (sep and "\n" or "") + b"\n".join(diff).decode('utf-8')
                              or ""))

    b.flush()
