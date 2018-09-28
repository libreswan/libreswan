# Identify a test's scripts.
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

import os
import re

from fab.hosts import HOST_NAMES

def _scripts(directory):
    """Returns a set of *.sh scripts found in DIRECTORY"""
    scripts = set()
    if os.path.isdir(directory):
        for script in os.listdir(directory):
            if not re.match(r"[a-z0-9].*\.sh$", script):
                continue
            path = os.path.join(directory, script)
            if not os.path.isfile(path):
                continue
            # Add more filter-outs
            scripts.add(script)
    return scripts

def _add_script(run, scripts, script, host_names):
    if script in scripts:
        scripts.remove(script)
        for host_name in host_names:
            run.append((host_name, script))

def host_script_tuples(directory):
    """Return a [] list of(host, script) tuples to run"""

    scripts = _scripts(directory)

    # Form a subset of HOST_NAMES based on the names found in the
    # scripts.
    host_names = set()
    for host_name in HOST_NAMES:
        for script in scripts:
            if re.search(host_name, script):
                host_names.add(host_name)

    # init scripts: nic, east, then rest
    init_scripts = []
    _add_script(init_scripts, scripts, "nicinit.sh", ["nic"])
    _add_script(init_scripts, scripts, "eastinit.sh", ["east"])
    for host_name in sorted(host_names):
        _add_script(init_scripts, scripts, host_name + "init.sh", [host_name])

    # run scripts
    run_scripts = []
    for host_name in sorted(host_names):
        _add_script(run_scripts, scripts, host_name + "run.sh", [host_name])

    # strip out the final script
    final_scripts = []
    _add_script(final_scripts, scripts, "final.sh", sorted(host_names))

    # What's left are ordered scripts.  Preserve the order that the
    # host names appear in the file name.  For instance, the script
    # 99-west-east.sh would be run on west then east.
    extra_scripts = []
    for script in sorted(scripts):
        for host_name in re.findall("|".join(host_names), script):
            extra_scripts.append((host_name, script))

    # append the final scripts
    all_scripts = []
    all_scripts.extend(init_scripts)
    all_scripts.extend(run_scripts)
    all_scripts.extend(extra_scripts)
    all_scripts.extend(final_scripts)
    return all_scripts
