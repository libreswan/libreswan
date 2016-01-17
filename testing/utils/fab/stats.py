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

    def add(self, key, value):
        self.counts[key].append(value)

    def log_summary(self, log, prefix=""):
        for key, values in sorted(self.counts.items()):
            log("%s%s: %d", prefix, key, len(values))

    def log_details(self, log, prefix=""):
        for key in sorted(self.counts):
            values = self.counts[key]
            line = ""
            for value in sorted(values):
                if value:
                    line += " "
                    line += value
            log("%s%s:%s", prefix, key, line)


class Tests(Counts):
    def add(self, stat, test):
        Counts.add(self, stat, test.name)


class Results(Counts):

    def count(self, result, *extras):
        Counts.add(self, "total", result.test.name)
        Counts.add(self, str(result), result.test.name)
        for extra in extras:
            Counts.add(self, "%s(%s)" % (result, extra), result.test.name)
        for error in result.errors:
            Counts.add(self, "%s(%s)" % (result, error), result.test.name)

    def add_ignore(self, test, reason):
        # result?
        Counts.add(self, "ignore", test.name)

    def add_skip(self, result):
        self.count(result, "skip-" + str(result))

    def add_result(self, result, old_result=None):
        if old_result:
            self.count(result, "previous-" + str(old_result))
        else:
            self.count(result)
