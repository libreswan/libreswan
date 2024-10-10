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
import re

from fab import utilsdir

def _guest_names():
    # this failing is a disaster
    output = subprocess.check_output([utilsdir.relpath("kvmhosts.sh")])

    guest_names = []
    for guest_name in output.decode('utf-8').splitlines():
        # match rise before e[ast]
        for h in ["rise", "set", "nic", "north", "south", "east", "west", "road"]:
            if re.search(h+r'$', guest_name):
                host_name = h
                break
            if re.search(h[0:1]+r'$', guest_name):
                host_name = h
                break
        t = (guest_name, host_name)
        guest_names.append(t)

    return guest_names

"""An unordered set of tuples of (GUEST_NAME,HOST_NAME)"""
GUEST_NAMES = _guest_names()

def _guest_to_host():
    d = dict()
    for guest_name, host_name in GUEST_NAMES:
        d[guest_name] = host_name
    return d

# A dictionary, with GUEST_NAME (as used to manipulate the domain
# externally) as the KEY and HOST_NAME (what `hostname` within the
# domain would return) as the value.
GUEST_TO_HOST = _guest_to_host()
