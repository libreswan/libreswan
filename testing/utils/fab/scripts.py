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
from glob import glob
from os import path

from fab import argutil
from fab import hosts

# In Command GUEST can be None because it is a blank line or comment.

class Command:
    def __init__(self, guest, line, script):
        self.guest = guest
        self.line = line
        self.script = script
    def __str__(self):
        if self.guest:
            if self.script:
                return self.script+" "+self.guest.name + "# " + self.line
            return self.guest.name + "# " + self.line
        return self.line

class Commands(list):
    def __str__(self):
        # string is used by --print test-scripts (it has no spaces)
        return "\n".join(str(script) for script in self)

def _scripts(directory):
    """Returns a set of *.sh scripts found in DIRECTORY"""
    scripts = set()
    for script in glob(path.join(directory, "*.sh")):
        if not path.isfile(script):
            continue
        # Add more filter-outs
        scripts.add(path.basename(script))
    return scripts

def _add_commands(script, commands, directory, guests):
    for guest in guests:
        for line in open(os.path.join(directory, script), "r"):
            # toss blank lines and trailing '\n'
            line = line.strip()
            if line:
                commands.append(Command(guest, line, script))

def _add_script(script, commands, scripts, directory, guests):
    if script in scripts:
        scripts.remove(script)
        _add_commands(script, commands, directory, guests)

def _script_guests(script, guests):
    matched = list()
    for guest in guests:
        if re.search(guest.name, script):
            matched.append(guest)
    return matched

def _guest_scripts(directory, logger):
    """Return a list of {guest_name:, path:} to run"""

    scripts = _scripts(directory)
    logger.debug("scripts: %s", scripts);

    # Form a subset of GUESTS based on the names found in the
    # scripts.
    guests = set()
    for script in scripts:
        guests.update(_script_guests(script, hosts.GUESTS))
    guests = sorted(guests)
    logger.debug("guests: %s", guests)

    # Compatibility hack: form a list of scripts matching <host>init.sh
    # and within that force "nic" then "east" to be on the front of
    # the list.  These will be run first.
    init_commands = Commands()
    _add_script("nicinit.sh", init_commands,
                scripts, directory, [hosts.NIC])
    _add_script("eastinit.sh", init_commands,
                scripts, directory, [hosts.EAST])
    for guest in guests:
        _add_script(guest.name+"init.sh", init_commands,
                    scripts, directory, [guest])
    logger.debug("init commands: %s", init_commands)

    # Compatibility hack: form a list of scripts matching <host>run.sh.
    # These will be run second.
    run_commands = Commands()
    for guest in guests:
        _add_script(guest.name+"run.sh", run_commands,
                    scripts, directory, [guest])
    logger.debug("run commands: %s", run_commands)

    # Part compatibility hack, part new behaviour: form a list of
    # scripts matching <host>final.sh.  These will be run last.
    final_commands = Commands()
    _add_script("final.sh", final_commands,
                scripts, directory, guests)
    logger.debug("final commands: %s", run_commands)

    # What's left are ordered scripts.  Preserve the order that the
    # host names appear in the file name.  For instance, the script
    # 99-west-east.sh would be run on west then east.
    ordered_commands = Commands()
    for script in sorted(scripts):
        _add_commands(script, ordered_commands, directory,
                      _script_guests(script, guests))
    logger.debug("ordered commands: %s", ordered_commands)

    # Form the list of scripts to run.  Per above: init, run, ordered,
    # final.
    all_commands = Commands()
    all_commands.extend(init_commands)
    all_commands.extend(run_commands)
    all_commands.extend(ordered_commands)
    all_commands.extend(final_commands)
    return all_commands

# for line in open("r").line includes; when <guest> is blank, a
# comment is assumed.

_GUEST_COMMAND_PATTERN = r'^(?P<guest>[a-z]*)# ?(?P<line>.*)[\n]$'
_GUEST_COMMAND_REGEX = re.compile(_GUEST_COMMAND_PATTERN)

def commands(directory, logger):

    for script in ("all.sh", "all.console.txt"):
        all = path.join(directory, script)
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
                        commands.append(Command(hosts.lookup(guest), line, script))
                    elif line:
                        commands.append(Command(guest, "# "+line, script))
                    else:
                        commands.append(Command(guest, "#", script))
            return commands

    return _guest_scripts(directory, logger)
