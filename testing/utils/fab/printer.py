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
    TEST_KIND = "test-kind"
    TEST_NAME = "test-name"
    TEST_COMMANDS = "test-commands"
    TEST_STATUS = "test-status"
    # results
    START_TIME = "start-time"
    STOP_TIME = "stop-time"
    BOOT_TIME = "boot-time"
    SCRIPT_TIME = "script-time"
    RUNTIME = "runtime"
    DIFFS = "diffs"
    ISSUES = "errors"                      # for historic reasons
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


def build_result(logger, result, args, what_to_print, b):

    # Print the test's name/path

    for p in what_to_print:
        if p is Print.PATH:
            # When the path given on the command line explicitly
            # specifies a test's output directory (found in
            # RESULT.TEST.SAVED_OUTPUT_DIRECTORY), print that; otherwise
            # print the path to the test's directory.
            b.add(p, (result.test.saved_output_directory
                      and result.test.saved_output_directory
                      or result.test.directory))
        elif p is Print.TEST_DIRECTORY:
            b.add(p, result.test.directory)
        elif p is Print.TEST_STATUS:
            b.add(p, result.test.status)
        elif p is Print.TEST_GUEST_NAMES:
            b.add(p, result.test.guest_names,
                  string=lambda guest_names, sep: sep + ",".join(guest_names))
        elif p is Print.TEST_KIND:
            b.add(p, result.test.kind)
        elif p is Print.TEST_NAME:
            b.add(p, result.test.name)
        elif p is Print.OUTPUT_DIRECTORY:
            b.add(p, result.test.output_directory)
        elif p is Print.RESULT:
            b.add(p, result)
        elif p is Print.ISSUES:
            b.add(p, result.issues)
        elif p is Print.TESTING_DIRECTORY:
            b.add(p, result.test.testing_directory())
        elif p is Print.SAVED_OUTPUT_DIRECTORY:
            b.add(p, result.test.saved_output_directory)
        elif p is Print.TEST_COMMANDS:
            b.add(p, result.test.commands)
        elif p is Print.START_TIME:
            b.add(p, result.start_time())
        elif p is Print.STOP_TIME:
            b.add(p, result.stop_time())
        elif p is Print.RUNTIME:
            b.add(p, result.runtime())
        elif p is Print.BOOT_TIME:
            b.add(p, result.boot_time())
        elif p is Print.SCRIPT_TIME:
            b.add(p, result.script_time())
        elif p is Print.DIFFS:
            continue # see below
        else:
            raise Exception("unhandled print option %s" % p)

    if Print.DIFFS in what_to_print:
        for guest_name, diff_output in result.diff_output.items():
            if diff_output: # could be blank
                b.add(Print.DIFFS, guest_name, diff_output,
                      string=(lambda diff, sep: diff
                              and (sep and "\n" or "") + b"\n".join(diff).decode('utf-8')
                              or ""))

    b.flush()
