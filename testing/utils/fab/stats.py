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

from fab import logutil

class Counts:

    def __init__(self):
        # Use a default dict so no need to worry about initializing
        # values to zero.
        self.counts = defaultdict(list)

    def add(self, value, *keys):
        key = "/".join(keys)
        self.counts[key].append(value)

    def log_summary(self, log, header=None, footer=None, prefix=""):
        if len(self.counts):
            header and log(header)
            for key, values in sorted(self.counts.items()):
                log("%s%s: %d", prefix, key, len(values))
            footer and log(footer)

    def log_details(self, log, header=None, footer=None, prefix=""):
        if len(self.counts):
            header and log(header)
            for key in sorted(self.counts):
                values = self.counts[key]
                line = ""
                for value in sorted(values):
                    if value:
                        line += " "
                        line += value
                log("%s%s:%s", prefix, key, line)
            footer and log(footer)


class Tests(Counts):
    def add(self, test, *stats):
        Counts.add(self, test.name, *stats)


class Results(Counts):

    def count(self, result):
        Counts.add(self, result.test.name, "total")
        Counts.add(self, result.test.name, str(result))
        for error in result.errors:
            Counts.add(self, result.test.name, str(result), error)

    def add_ignore(self, test, reason):
        Counts.add(self, test.name, "total")
        Counts.add(self, test.name, "ignore", reason)

    def add_skip(self, result):
        self.count(result)
        Counts.add(self, result.test.name, "skip", str(result))

    def add_result(self, result, old_result=None):
        self.count(result)
        if old_result:
            Counts.add(self, result.test.name, "previous", str(old_result))
