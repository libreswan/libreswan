# Hosts
#
# Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

import subprocess

from fab import utilsdir

def _host_names():
    host_names = set()
    status, output = subprocess.getstatusoutput(utilsdir.relpath("kvmhosts.sh"))
    for host_name in output.splitlines():
        host_names.add(host_name)
    return host_names

"""An unordered set of the test host names"""
HOST_NAMES = _host_names()
