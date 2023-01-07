# Hosts
#
# Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

import subprocess

from fab import utilsdir

def _guest_names():
    guest_names = set()
    # this failing is a disaster
    output = subprocess.check_output([utilsdir.relpath("kvmhosts.sh")])
    for guest_name in output.decode('utf-8').splitlines():
        guest_names.add(guest_name)
    return guest_names

"""An unordered set of the test guest names"""
GUEST_NAMES = _guest_names()
