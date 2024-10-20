# Perform post.mortem on a test result, for libreswan.
#
# Copyright (C) 2015-2024 Andrew Cagney
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

class Resolution:
    def __init__(self):
        self.state = None
    def __str__(self):
        return self.state
    def __eq__(self, rhs):
        return self.state == rhs
    def isresolved(self):
        return self.state in [PASSED, FAILED]
    def unsupported(self):
        assert(self.state in [None])
        self.state = UNSUPPORTED
    def untested(self):
        assert(self.state in [None])
        self.state = UNTESTED
    def passed(self):
        assert(self.state in [None])
        self.state = PASSED
    def failed(self):
        assert(self.state in [FAILED, PASSED, UNRESOLVED])
        if self.state in [FAILED, PASSED]:
            self.state = FAILED
    def unresolved(self):
        assert(self.state in [PASSED, FAILED, UNRESOLVED, None])
        self.state = UNRESOLVED

PASSED = "passed"
FAILED = "failed"
UNRESOLVED = "unresolved"
UNTESTED = "untested"
UNSUPPORTED = "unsupported"
