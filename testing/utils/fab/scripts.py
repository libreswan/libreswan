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

from fab import argutil

class Scripts(list):
    def __str__(self):
        # string is used by --print test-scripts (it has no spaces)
        return ",".join(str(script) for script in self)

class Script:
    def __init__(self, host_name, path):
        self.host_name = host_name
        self.path = path
    def __str__(self):
        return self.host_name + ":" + self.path

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
            run.append(Script(host_name, script))

def host_scripts(directory, logger):
    """Return a list of (host, script, silent-but-deadly) tuples to run"""

    scripts = _scripts(directory)
    logger.debug("raw script files: %s", scripts);

    # Form a subset of HOST_NAMES based on the names found in the
    # scripts.
    host_names = set()
    for host_name in HOST_NAMES:
        for script in scripts:
            if re.search(host_name, script):
                host_names.add(host_name)
    host_names = sorted(host_names)
    logger.debug("script sorted host names: %s", host_names)

    # Compatiblity hack: form a list of scripts matching <host>init.sh
    # and within that force "nic" then "east" to be on the front of
    # the list.  These will be run first.
    init_scripts = Scripts()
    _add_script(init_scripts, scripts, "nicinit.sh", ["nic"])
    _add_script(init_scripts, scripts, "eastinit.sh", ["east"])
    for host_name in host_names:
        _add_script(init_scripts, scripts, host_name + "init.sh", [host_name])
    logger.debug("init scripts: %s", init_scripts)

    # Compatiblity hack: form a list of scripts matching <host>run.sh.
    # These will be run second.
    run_scripts = Scripts()
    for host_name in host_names:
        _add_script(run_scripts, scripts, host_name + "run.sh", [host_name])
    logger.debug("run scripts: %s", run_scripts)

    # Part compatiblity hack, part new behaviour: form a list of
    # scripts matching <host>final.sh.  These will be run last.
    final_scripts = Scripts()
    _add_script(final_scripts, scripts, "final.sh", host_names)
    logger.debug("final scripts: %s", final_scripts)

    # What's left are ordered scripts.  Preserve the order that the
    # host names appear in the file name.  For instance, the script
    # 99-west-east.sh would be run on west then east.
    ordered_scripts = Scripts()
    for script in sorted(scripts):
        for host_name in re.findall("|".join(host_names), script):
            ordered_scripts.append(Script(host_name, script))
    logger.debug("ordered scripts: %s", ordered_scripts)

    # Form the list if scripts to run.  Per above: init, run, ordered,
    # final.
    all_scripts = Scripts()
    all_scripts.extend(init_scripts)
    all_scripts.extend(run_scripts)
    all_scripts.extend(ordered_scripts)
    all_scripts.extend(final_scripts)
    return all_scripts
