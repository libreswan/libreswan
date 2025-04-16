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

_INTERESTING = ("total/failed", "total/unresolved")

class Results:

    def __init__(self):
        # Use a default dict so no need to worry about initializing
        # values to zero.
        self.counts = defaultdict(lambda: defaultdict(set))
        self.lock = threading.Lock()

    def _add(self, *keys_value, domain=None):
        keys = keys_value[0:-1]
        value = keys_value[-1]
        with self.lock:
            key = "/".join(keys)
            # Include the "None" domain in the set so that it is always
            # non-empty - makes iterating over it is easier.  See
            # log_details.
            self.counts[key][value].add(domain)

    def log_summary(self, log):
        with self.lock:
            if len(self.counts):
                log("Summary:")
                for key, values in sorted(self.counts.items()):
                    log(f"  {key}: {len(values)}")

    def log_progress(self, log):
        with self.lock:
            if len(self.counts):
                log("Progress:")
                for key, values in sorted(self.counts.items()):
                    if key in _INTERESTING:
                        log(f"  {key}: {len(values)} {" ".join(values)}")
                    else:
                        log(f"  {key}: {len(values)}")

    def log_details(self, log):
        with self.lock:
            if len(self.counts):
                log("Details:")
                for key in _INTERESTING:
                    if key in self.counts:
                        values = self.counts[key]
                        log(f"  {key}: {" ".join(values)}")
                log("Summary:")
                for key, values in sorted(self.counts.items()):
                    log(f"  {key}: {len(values)}")

    def log_tmi(self, log, header=None, footer=None, prefix=""):
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

    def _count_result(self, result):
        self._add("total",                                             result.test.name)
        self._add("total",                                str(result), result.test.name)
        self._add("tests", result.test.status, "results", str(result), result.test.name)
        # details
        for issue in result.issues:
            for domain in result.issues[issue]:
                self._add("tests", result.test.status, "errors", issue, result.test.name, domain=domain)

    def _count_previous(self, result, previous):
        self._add("stats", previous.test.status,
                   result, "previous=" + str(previous), previous.test.name)

    def add_ignored(self, test, reason):
        """The test has been excluded from the test run"""
        self._add("total", test.name)
        self._add("total", "ignored", test.name)
        self._add("tests", test.status, "results", "untested", test.name)
        self._add("stats", test.status, "ignored", reason, test.name)

    def add_skipped(self, result):
        """The test wasn't run; log the previous result"""
        self._count_result(result)
        self._count_previous("skipped", result)

    def add_result(self, result, old_result=None):
        self._count_result(result)
        if old_result:
            self._count_previous(str(result), old_result)
