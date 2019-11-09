# Some when did this program start?
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

# Everything uses this as the reference time.  There must be a more
# correct way.

from datetime import datetime


START_TIME = datetime.now()


class Lapsed:
    """A lapsed timer that prints as seconds by default

    As part of 'with' it automatically starts/stops.

    """

    def __init__(self, start=None):
        self.start = start or datetime.now()
        self.stop = None

    def format(self, now=None):
        now = now or self.stop or datetime.now()
        delta = now - self.start
        deciseconds = (delta.microseconds / 100000)
        seconds = delta.seconds % 60
        minutes = (delta.seconds // 60) % 60
        hours = (delta.seconds // 60 // 60) % 24
        days = delta.days
        if days > 0:
            # need days
            return str(delta)
        elif hours > 0:
            return "%d:%02d:%02d.%02d" % (hours, minutes, seconds,
                                          deciseconds)
        elif minutes > 0:
            return "%d:%02d.%02d" % (minutes, seconds, deciseconds)
        else:
            return "%d.%02d" % (seconds, deciseconds)

    def seconds(self, now=None):
        now = now or self.stop or datetime.now()
        delta = now - self.start
        return delta.total_seconds()

    def __enter__(self):
        self.start = datetime.now()
        return self

    def __exit__(self, type, value, traceback):
        self.stop = datetime.now()

    def __str__(self):
        return "%.01f seconds" % self.seconds()
