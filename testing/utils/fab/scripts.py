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
from fab import hosts

class Scripts(list):
    def __str__(self):
        # string is used by --print test-scripts (it has no spaces)
        return ",".join(str(script) for script in self)

class Script:
    def __init__(self, guest_name, path):
        self.guest_name = guest_name
        self.path = path
    def __str__(self):
        return self.guest_name + ":" + self.path

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

def _add_script(run, scripts, script, guest_names):
    if script in scripts:
        scripts.remove(script)
        for guest_name in guest_names:
            run.append(Script(guest_name, script))

def _guest_scripts(directory, logger):
    """Return a list of {guest_name:, path:} to run"""

    scripts = _scripts(directory)
    logger.debug("raw script files: %s", scripts);

    # Form a subset of GUEST_NAMES based on the names found in the
    # scripts.
    guest_names = set()
    for guest_name, host_name in hosts.GUEST_NAMES:
        for script in scripts:
            if re.search(guest_name, script):
                guest_names.add(guest_name)
    guest_names = sorted(guest_names)
    logger.debug("script sorted host names: %s", guest_names)

    # Compatibility hack: form a list of scripts matching <host>init.sh
    # and within that force "nic" then "east" to be on the front of
    # the list.  These will be run first.
    init_scripts = Scripts()
    _add_script(init_scripts, scripts, "nicinit.sh", ["nic"])
    _add_script(init_scripts, scripts, "eastinit.sh", ["east"])
    for guest_name in guest_names:
        _add_script(init_scripts, scripts, guest_name + "init.sh", [guest_name])
    logger.debug("init scripts: %s", init_scripts)

    # Compatibility hack: form a list of scripts matching <host>run.sh.
    # These will be run second.
    run_scripts = Scripts()
    for guest_name in guest_names:
        _add_script(run_scripts, scripts, guest_name + "run.sh", [guest_name])
    logger.debug("run scripts: %s", run_scripts)

    # Part compatibility hack, part new behaviour: form a list of
    # scripts matching <host>final.sh.  These will be run last.
    final_scripts = Scripts()
    _add_script(final_scripts, scripts, "final.sh", guest_names)
    logger.debug("final scripts: %s", final_scripts)

    # What's left are ordered scripts.  Preserve the order that the
    # host names appear in the file name.  For instance, the script
    # 99-west-east.sh would be run on west then east.
    ordered_scripts = Scripts()
    for script in sorted(scripts):
        for guest_name in re.findall("|".join(guest_names), script):
            ordered_scripts.append(Script(guest_name, script))
    logger.debug("ordered scripts: %s", ordered_scripts)

    # Form the list of scripts to run.  Per above: init, run, ordered,
    # final.
    all_scripts = Scripts()
    all_scripts.extend(init_scripts)
    all_scripts.extend(run_scripts)
    all_scripts.extend(ordered_scripts)
    all_scripts.extend(final_scripts)
    return all_scripts

class Command:
    def __init__(self, guest_name, line):
        self.guest_name = guest_name
        self.host_name = guest_name and hosts.GUEST_TO_HOST[guest_name]
        self.line = line
    def __str__(self):
        if self.guest_name:
            return self.guest_name + "# " + self.line
        else:
            return self.line

class Commands(list):
    def __str__(self):
        # string is used by --print test-scripts (it has no spaces)
        return "\n".join(str(script) for script in self)

# for line in open("r").line includes; when <guest> is blank, a
# comment is assumed.

_GUEST_COMMAND_PATTERN = r'^(?P<guest>[a-z]*)# ?(?P<line>.*)[\n]$'
_GUEST_COMMAND_REGEX = re.compile(_GUEST_COMMAND_PATTERN)

def commands(directory, logger):

    all_sh = os.path.join(directory, "all.sh")
    all_console_txt = os.path.join(directory, "all.console.txt")
    for all in (all_sh, all_console_txt):
        if os.path.exists(all):
            commands = Commands()
            # read includes '\n';
            for line in open(all, "r"):
                # regex matches both:
                #   <host># command
                # and
                #   # comment
                command = _GUEST_COMMAND_REGEX.match(line)
                if command:
                    guest = command.group("guest")
                    line = command.group("line")
                    if guest:
                        commands.append(Command(guest, line))
                    elif line:
                        commands.append(Command(guest, "# "+line))
                    else:
                        commands.append(Command(guest, "#"))
            return commands

    commands = Commands()
    scripts = _guest_scripts(directory, logger)
    for script in scripts:
        for line in open(os.path.join(directory, script.path), "r"):
            # toss blank lines and trailing '\n'
            line = line.strip()
            if line:
                command = Command(script.guest_name, line)
                commands.append(command)

    return commands
