# A multi-output file, for libreswan.
#
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

def open(*streams, files=[]):
    return Tee(*streams, files=files)

class Tee:

    def __init__(self, *streams, files=[]):
        self.files = files
        self.streams = []
        for s in streams:
            self.streams.append(s)
        for f in files:
            self.streams.append(f)

    def close(self):
        for f in self.files:
            f.close()

    def write(self, text):
        for s in self.streams:
            s.write(text)

    def flush(self):
        for s in self.streams:
            s.flush()
