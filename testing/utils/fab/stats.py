#!/usr/bin/env python3

# Collect test statistics
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


class Results(Counts):

    def add_ignored(self, test, reason):
        Counts.add(self, test.name, "total")
        Counts.add(self, test.name, "ignored")
        Counts.add(self, test.name, "ignored", reason)

    def count_result(self, result):
        Counts.add(self, result.test.name, "total")
        Counts.add(self, result.test.name, str(result))
        for domain, errors in result.errors.items():
            for error in errors:
                Counts.add(self, result.test.name, str(result), error, domain=domain)

    def add_skipped(self, result):
        Counts.add(self, result.test.name, "skipped", str(result))
        self.count_result(result)

    def add_result(self, result, old_result=None):
        self.count_result(result)
        if old_result:
            Counts.add(self, result.test.name, str(result), "previous", str(old_result))
