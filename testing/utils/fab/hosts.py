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

import re
from os import path

from fab import utilsdir

class Host:
    def __init__(self, name):
        self.name = name
    def __str__(self):
        return self.name
    def __lt__(self, peer):
        return self.name < peer.name

class Guest:
    def __init__(self, host, platform=None, guest=None):
        self.platform = platform	# netbsd, freebsd, ...
        self.host = host		# east, west, ...
        self.name = guest or host.name
    def __str__(self):
        return self.name
    def __lt__(self, peer):
        return self.name < peer.name

class Set(set):
    def __str__(self):
        return " ".join(str(s) for s in self)

HOSTS = Set()
for xml in utilsdir.glob("../kvm/vm/*.xml"):
    host = re.match(r'^.*/(.*).xml$', xml).group(1)
    # For hosts, ignor E,W,N,...
    if len(host) == 1:
        continue
    HOSTS.add(Host(host))

# should have kvm/platform/*
PLATFORMS = Set()
for t in utilsdir.glob("../kvm/*/upgrade.sh"):
    # after the "*" in pattern
    p = path.basename(path.dirname(t))
    PLATFORMS.add(p)

GUESTS = Set()
for host in HOSTS:
    if host.name in ("rise", "set"):
        for platform in PLATFORMS:
            GUESTS.add(Guest(host, platform, platform+host.name))
        continue
    if host.name in ("east", "west"):
        GUESTS.add(Guest(host))
        for platform in PLATFORMS:
            GUESTS.add(Guest(host, platform, platform+host.name[0:1]))
        continue
    GUESTS.add(Guest(host))

# A dictionary, with GUEST_NAME (as used to manipulate the domain
# externally) as the KEY and HOST_NAME (what `hostname` within the
# domain would return) as the value.

_LOOKUP = dict()
for guest in GUESTS:
    _LOOKUP[guest.name] = guest

def lookup(name):
    if name in _LOOKUP:
        return _LOOKUP[name]
    return None

NIC = _LOOKUP["nic"]
EAST = _LOOKUP["east"]
