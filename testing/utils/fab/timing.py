# Some when did this program start?
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

# Everything uses this as the reference time.  There must be a more
# correct way.

from datetime import datetime


START_TIME = datetime.now()


class Lapsed:
    """A lapsed timer with second granularity"""

    def __init__(self, start=None):
        self.start = start or datetime.now()

    def format(self, now=None):
        now = now or datetime.now()
        delta = now - self.start
        milliseconds = (delta.microseconds / 1000)
        seconds = delta.seconds % 60
        minutes = (delta.seconds // 60) % 60
        hours = (delta.seconds // 60 // 60) % 24
        days = delta.days
        if days > 0:
            # need days
            return str(delta)
        elif hours > 0:
            return "%d:%02d:%02d.%03d" % (hours, minutes, seconds, milliseconds)
        elif minutes > 0:
            return "%d:%02d.%03d" % (minutes, seconds, milliseconds)
        else:
            return "%d.%03d" % (seconds, milliseconds)

    def seconds(self, now=None):
        now = now or datetime.now()
        delta = now - self.start
        return delta.total_seconds()

    def __str__(self):
        seconds = round(self.seconds())
        if seconds == 1:
            return "1 second"
        else:
            return "%d seconds" % seconds


class LapsedStack:
    """A stack of lapsed timers; "with" creates a new level."""

    def __init__(self):
        self.runtimes = [Lapsed(START_TIME)]

    def __enter__(self):
        self.runtimes.append(Lapsed())
        return self.runtimes[-1]

    def __exit__(self, type, value, traceback):
        self.runtimes.pop()

    def __str__(self):
        runtimes = ""
        now = datetime.now()
        for runtime in self.runtimes:
            if runtimes:
                runtimes += "/"
            runtimes += runtime.format(now)
        return runtimes
