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

class Set(set):
    def __str__(self):
        return " ".join(str(s) for s in self)
class Dict(dict):
    def __str__(self):
        return " ".join(str(s) for s in self)
class List(list):
    def __str__(self):
        return " ".join(str(s) for s in self)

class Host:
    def __init__(self, name):
        self.name = name	# east, e, rise, ...
    def __str__(self):
        return self.name
    def __lt__(self, peer):
        return self.name < peer.name

class Guest:
    def __init__(self, host, platform):
        self.platform = platform
        self.host = host
        self.name = platform+host.name
    def __str__(self):
        return self.name
    def __lt__(self, peer):
        return self.name < peer.name

_HOSTS = Dict() # east west rise set ...
for xml in utilsdir.glob("../kvm/vm/*.xml"):
    hostname = re.match(r'^.*/(.*).xml$', xml).group(1)
    host = Host(hostname)
    _HOSTS[host.name] = host

PLATFORMS = Set() # netbsd freebsd fedora ...
for t in utilsdir.glob("../kvm/platform/*/upgrade.sh"):
    # what matched "*" in above pattern
    p = path.basename(path.dirname(t))
    PLATFORMS.add(p)

_GUESTS = Dict() # netbsdrise fedoraset east freebsdwest ...
_ALL_LINUX_GUESTS = Set() # nic east west ... ordered
for host in sorted(_HOSTS.values()):
    for platform in PLATFORMS:
        guest = Guest(host, platform)
        match platform:
            case "linux":
                # east west ...
                _GUESTS[guest.name] = guest
                _GUESTS[host.name] = guest # also add linuxEAST et.al.
                _ALL_LINUX_GUESTS.add(guest)
            case _:
                if host in ("nic", "road"): # not yet
                    continue
                # netbsdrise netbsdnorth ...
                _GUESTS[guest.name] = guest

# NIC and EAST are special
NIC = _GUESTS["nic"]
EAST = _GUESTS["east"]

# force NIC, EAST to be first
LINUX_GUESTS = [NIC, EAST]
for guest in LINUX_GUESTS:
    _ALL_LINUX_GUESTS.remove(guest)
LINUX_GUESTS.extend(sorted(_ALL_LINUX_GUESTS))


# A dictionary, with GUEST_NAME (as used to manipulate the domain
# externally) as the KEY and HOST_NAME (what `hostname` within the
# domain would return) as the value.

def guest_by_guestname(guestname):
    if guestname in _GUESTS:
        return _GUESTS[guestname]
    return None

def guests():
    return _GUESTS.values()

# \b(east|west|...)\b
_GUEST_PATTERN = re.compile(r"\b(" + "|".join(_GUESTS.keys()) + r")\b")
def guests_by_filename(filename):
    guestnames = _GUEST_PATTERN.findall(filename)
    guests = List()
    for guestname in guestnames:
        guests.append(_GUESTS[guestname])
    return guests
