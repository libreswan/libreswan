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
import time

START_TIME = datetime.now()


class Lapsed:
    """A lapsed timer with second granularity"""

    def __init__(self):
        self.start = time.time()

    def __str__(self):
        lapsed = round(time.time() - self.start)
        if lapsed == 1:
            return "1 second"
        else:
            return "%d seconds" % lapsed


class LapsedTime:
    """A lapsed timer with millisecond granularity"""

    def __init__(self, start=None):
        self.start = start or datetime.now()

    def lapsed(self, now):
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

    def __str__(self):
        return self.lapsed(datetime.now())
