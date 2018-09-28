#!/usr/bin/env python3

# Collect test statistics
#
# Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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

from collections import defaultdict
import threading

from fab import logutil

class Counts:

    def __init__(self):
        # Use a default dict so no need to worry about initializing
        # values to zero.
        self.counts = defaultdict(lambda: defaultdict(set))
        self.lock = threading.Lock()

    def add(self, value, *keys, domain=None):
        with self.lock:
            key = "/".join(keys)
            # Include the "None" domain in the set so that it is always
            # non-empty - makes iterating over it is easier.  See
            # log_details.
            self.counts[key][value].add(domain)

    def log_summary(self, log, header=None, footer=None, prefix=""):
        with self.lock:
            if len(self.counts):
                header and log(header)
                for key, values in sorted(self.counts.items()):
                    log("%s%s: %d", prefix, key, len(values))
                footer and log(footer)

    def log_details(self, log, header=None, footer=None, prefix=""):
        with self.lock:
            if len(self.counts):
                header and log(header)
                for key, values in sorted(self.counts.items()):
                    # First invert value:domain creating domain:value
                    table = defaultdict(set)
                    for value, domains in sorted(values.items()):
                        for domain in domains:
                            table[domain].add(value)
                    # Second log key[/domain]: value ...
                    for domain, values in sorted(table.items()):
                        line = ""
                        for value in sorted(values):
                            line += " " + value
                        if domain:
                            log("%s%s/%s:%s", prefix, key, domain, line)
                        else:
                            log("%s%s:%s", prefix, key, line)
                footer and log(footer)


class Tests(Counts):
    def add(self, test, *stats):
        Counts.add(self, test.name, *stats)

# Record results:
#
# total/{passed,failed,ignored,unresolved} must add up

class Results(Counts):

    def count_result(self, result):
        Counts.add(self, result.test.name, "total")
        Counts.add(self, result.test.name, "total", str(result))
        Counts.add(self, result.test.name, "total", str(result), result.test.status)
        # details
        for issue in result.issues:
            for domain in result.issues[issue]:
                Counts.add(self, result.test.name, "total", str(result),
                           result.test.status, issue, domain=domain)

    def count_previous(self, result, previous):
        Counts.add(self, previous.test.name,
                   "status", previous.test.status,
                   result, "previous=" + str(previous))

    def add_ignored(self, test, reason):
        """The test has been excluded from the test run"""
        Counts.add(self, test.name, "total")
        Counts.add(self, test.name, "total", "ignored")
        Counts.add(self, test.name,
                   "status", test.status,
                   "ignored", reason)

    def add_skipped(self, result):
        """The test wasn't run; log the previous result"""
        self.count_result(result)
        self.count_previous("skipped", result)

    def add_result(self, result, old_result=None):
        self.count_result(result)
        if old_result:
            self.count_previous(str(result), old_result)
