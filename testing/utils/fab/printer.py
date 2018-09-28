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
    test_directory = "test-directory"
    test_host_names = "test-host-names"
    test_kind = "test-kind"
    test_name = "test-name"
    test_scripts = "test-scripts"
    test_status = "test-status"
    # results
    boot_time = "boot-time"
    diffs = "diffs"
    end_time = "end-time"
    issues = "errors"                      # for historic reasons
    expected_result = "expected-result"    # test_status
    host_names = "host-names"              # test_host_names
    kind = "kind"                          # test_kind
    output_directory = "output-directory"
    path = "path"
    result = "result"
    runtime = "runtime"
    saved_output_directory = "saved-output-directory"
    script_time = "script-time"
    scripts = "scripts"                    # test_scripts
    start_time = "start-time"
    testing_directory = "testing-directory"
    baseline_directory = "baseline-directory"
    baseline_output_directory = "baseline-output-directory"


class JsonBuilder:
    def __init__(self, stream=None):
        self.stream = stream
        self.table = {}
    def prefix(self, key, value):
        self.add(str(key), value)
    def add(self, *keyval, string=None):
        keys = [key.replace("-","_") for key in keyval[0:-1]]
        value = keyval[-1]
        # Only suppress non-existant values.
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


def build_result(logger, result, baseline, args, what_to_print, b):

    # Print the test's name/path

    for p in what_to_print:
        if p is Print.path:
            # When the path given on the command line explicitly
            # specifies a test's output directory (found in
            # RESULT.TEST.SAVED_OUTPUT_DIRECTORY), print that; otherwise
            # print the path to the test's directory.
            b.add(p, (result.test.saved_output_directory
                      and result.test.saved_output_directory
                      or result.test.directory))
        elif p is Print.test_directory:
            b.add(p, result.test.directory)
        elif p is Print.test_status or p is Print.expected_result:
            b.add(p, result.test.status)
        elif p is Print.test_host_names or p is Print.host_names:
            b.add(p, result.test.host_names,
                  string=lambda host_names, sep: sep + ",".join(host_names))
        elif p is Print.test_kind or p is Print.kind:
            b.add(p, result.test.kind)
        elif p is Print.test_name:
            b.add(p, result.test.name)
        elif p is Print.output_directory:
            b.add(p, result.test.output_directory)
        elif p is Print.result:
            b.add(p, result)
        elif p is Print.issues:
            b.add(p, result.issues)
        elif p is Print.testing_directory:
            b.add(p, result.test.testing_directory())
        elif p is Print.saved_output_directory:
            b.add(p, result.test.saved_output_directory)
        elif p is Print.test_scripts or p is Print.scripts:
            b.add(p, [{ "host": h, "script": s} for h, s in result.test.host_script_tuples],
                  string=lambda scripts, sep: sep + ",".join([script["host"] + ":" + script["script"] for script in scripts]))
        elif p is Print.baseline_directory:
            b.add(p, baseline and result.test.name in baseline and baseline[result.test.name].directory or None)
        elif p is Print.baseline_output_directory:
            b.add(p, baseline and result.test.name in baseline and baseline[result.test.name].output_directory or None)
        elif p is Print.start_time:
            b.add(p, result.start_time())
        elif p is Print.end_time:
            b.add(p, result.end_time())
        elif p is Print.runtime:
            b.add(p, result.runtime())
        elif p is Print.boot_time:
            b.add(p, result.boot_time())
        elif p is Print.script_time:
            b.add(p, result.script_time())
        elif p is Print.diffs:
            continue # see below
        else:
            raise Exception("unhandled print option %s" % p)

    if Print.diffs in what_to_print:
        for domain in result.diffs:
            b.add(Print.diffs, domain, result.diffs[domain],
                  string=(lambda diff, sep: diff
                          and (sep and "\n" or "") + "\n".join(diff)
                          or ""))

    b.flush()
