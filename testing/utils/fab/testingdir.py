# Utils directory, for libreswan
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

from pathlib import Path
import sys

# Assuming argv[0] is .../testing/util/{kvmrunner,kvmresults,kvmsh}
# form TESTINGDIR (.../testing) as an absolute path.  Need to first
# .resolve() to eliminate anything relative (see .parent() docs).

_TESTINGDIR = Path(sys.argv[0]).resolve().parent.parent

def joinpath(*pathsegments):
    return _TESTINGDIR.joinpath(*pathsegments)

def glob(*pattern):
    return _TESTINGDIR.glob(*pattern)
