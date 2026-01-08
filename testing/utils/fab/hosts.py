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
        self.name = name	# east, e, rise, ...
    def __str__(self):
        return self.name
    def __lt__(self, peer):
        return self.name < peer.name

class Guest:
    def __init__(self, host, platform=None, guest=None):
        self.platform = platform  # Platform("netbsd"), ...
        self.host = host	  # see Host("east"), ...
        self.name = guest	  # netbsde, ...
    def __str__(self):
        return self.name
    def __lt__(self, peer):
        return self.name < peer.name

class Set(set):
    def __str__(self):
        return " ".join(str(s) for s in self)
class Dict(dict):
    def __str__(self):
        return " ".join(str(s) for s in self)

_HOSTS = Dict() # east west rise set ...
for xml in utilsdir.glob("../kvm/vm/*.xml"):
    hostname = re.match(r'^.*/(.*).xml$', xml).group(1)
    # For hosts, ignor E,W,N,...
    if len(hostname) == 1:
        continue
    host = Host(hostname)
    _HOSTS[host.name] = host

PLATFORMS = Set() # netbsd freebsd fedora ...
for t in utilsdir.glob("../kvm/platform/*/upgrade.sh"):
    # what matched "*" in above pattern
    p = path.basename(path.dirname(t))
    PLATFORMS.add(p)

_GUESTS = Dict() # netbsdrise fedoraset east freebsdw ...
LINUX_GUESTS = list() # east west ... SORTED
for host in _HOSTS.values():
    if host.name in ("rise", "set"):
        for platform in PLATFORMS:
            if platform not in "linux":
                # netbsdrise netbsdset ...
                guest = Guest(host, platform, guest=platform+host.name)
                _GUESTS[guest.name] = guest
        continue
    if host.name in ("east", "west"):
        # east west ...
        guest = Guest(host, platform="linux", guest=host.name)
        _GUESTS[guest.name] = guest
        LINUX_GUESTS.append(guest)
        for platform in PLATFORMS:
            if platform not in "linux":
                # netbsde netbsdw ...
                guest = Guest(host, platform, guest=platform+host.name[0:1])
                _GUESTS[guest.name] = guest
        continue
    guest = Guest(host, platform="linux", guest=host.name)
    _GUESTS[guest.name] = guest
    LINUX_GUESTS.append(guest)
LINUX_GUESTS = sorted(LINUX_GUESTS)

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
    guests = list()
    for guestname in guestnames:
        guests.append(_GUESTS[guestname])
    return guests

# NIC and EAST are first

NIC = _GUESTS["nic"]
EAST = _GUESTS["east"]
