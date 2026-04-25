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

from fab.datautil import *
from fab import argutil
from fab import hosts

# In Command GUEST can be None because LINE (the command) is either a
# blank line or a comment.

class Command:
    def __init__(self, guest, line, script, line_nr):
        self.guest = guest
        self.line = line
        self.script = script
        self.line_nr = line_nr
    def __str__(self):
        if self.guest:
            return f"{self.script}:{self.line_nr}: {self.guest.name}# {self.line}"
        return f"{self.script}:{self.line_nr}: {self.line}"

class Commands(list):
    def __str__(self):
        # string is used by --print test-scripts (it has no spaces)
        return "\n".join(str(script) for script in self)

def _scripts(directory):
    """Returns a set of *.sh scripts found in DIRECTORY"""
    scripts = Set()
    for script in glob(path.join(directory, "*.sh")):
        if not path.isfile(script):
            continue
        # Add more filter-outs
        scripts.add(path.basename(script))
    return scripts

def _add_script_commands(script, commands, directory, guest):
    line_nr = 0
    for line in open(os.path.join(directory, script), "r"):
        line_nr += 1
        # toss blank lines and trailing '\n'
        line = line.strip()
        if line:
            commands.append(Command(guest, line, script, line_nr))

def _add_script(script, commands, scripts, directory,
                script_guests, test_guests):
    if script_guests and script in scripts:
        scripts.remove(script)
        for guest in script_guests:
            test_guests.add(guest)
            _add_script_commands(script, commands, directory, guest)


# *.sh

def _guest_scripts(directory, logger):
    """Return a list of {guestname:, path:} to run"""

    scripts = _scripts(directory)
    logger.debug(f"*.sh scripts: {scripts}");
    guests = Set()

    # Compatibility hack:
    #
    # Find the commands matching <hostname>init.sh.
    #
    # The array LINUX_GUESTS is ordered, ["nic", "east" ...] forcing
    # those scripts to be run first.

    init_commands = Commands()
    for guest in hosts.LINUX_GUESTS:
        hostname = guest.host.name
        _add_script(f"{hostname}init.sh",
                    init_commands,
                    scripts, directory,
                    [guest], guests)
    logger.debug(f"*init.sh: guests: {guests} scripts: {scripts}; {init_commands}")

    # Compatibility hack:
    #
    # Find the commands matching <hostname>run.sh.  These will be run
    # second.
    #
    # The array LINUX_GUESTS is ordered, ["nic", "east", ...] forcing
    # those scripts to be run first.

    run_commands = Commands()
    for guest in hosts.LINUX_GUESTS:
        hostname = guest.host.name
        _add_script(f"{hostname}run.sh", run_commands,
                    scripts, directory,
                    [guest], guests)
    logger.debug(f"*run.sh: guests: {guests} scripts: {scripts}; {run_commands}")

    # Look for scripts matching \b<hostname>\b.
    #
    # Preserve the order that the host names appear in the file name.
    # For instance, the script 99-west-east.sh would be run on west
    # then east.

    ordered_commands = Commands()
    for script in sorted(scripts):
        _add_script(script, ordered_commands,
                    scripts, directory,
                    hosts.guests_by_filename(script),
                    guests)
    logger.debug(f"*HOSTNAME*.sh commands guests: {guests} scripts: {scripts}; {ordered_commands}")

    # Part compatibility hack.
    #
    # part new behaviour: form a list of scripts matching final.sh.
    # These will be run last.

    final_commands = Commands()
    _add_script("final.sh", final_commands,
                scripts, directory,
                sorted(guests), guests)
    logger.debug(f"final.sh: guests: {guests} scripts: {scripts}; {final_commands}")

    commands = Commands()
    commands.extend(init_commands)
    commands.extend(run_commands)
    commands.extend(ordered_commands)
    commands.extend(final_commands)
    guests = Sorted(guests)

    logger.debug(f"commands: guests: {guests} scripts: {scripts}; {commands}")
    return (guests, commands)

# Return the tupple (GUESTS, COMMANDS)

_HOSTNAME_COMMAND_REGEX = re.compile(r'^(?P<hostname>[a-z]*)# ?(?P<command>.*)[\n]$')

def commands(directory, logger):

    # Match experimental all.*GUESTNAME*.sh file.
    #
    # GUESTNAME == <PLATFORM><HOSTNAME> identifies the domains to
    # boot.  Within the file are 'HOST# ...' lines identifying the
    # HOST to run the command on.
    #
    # Match this before '*.sh' so that '*.sh" isn't confused by
    # guestnames.

    scripts = glob(path.join(directory, "all.*.sh"))
    if scripts:

        if len(scripts) > 1:
            logger.error(f"multiple script files: {' '.join(scripts)}");
            return (None, None)

        script = scripts[0];
        if not path.isfile(script):
            logger.error(f"script {script} is not a file?!?")
            return (None, None)

        # figure out the host->guest map
        guests = hosts.guests_by_filename(script)
        logger.debug(f"script: {script}; guests: {guests};")

        GUEST_BY_HOSTNAME = Dict()
        for guest in guests:
            GUEST_BY_HOSTNAME[guest.host.name] = guest
        logger.debug(f"GUEST_BY_HOSTNAME: {GUEST_BY_HOSTNAME}")

        commands = Commands()
        line_nr = 0
        for line in open(script, "r"):
            line_nr += 1
            logger.debug(f"{line[0:-1]}")
            # regex matches both:
            #   <hostname># command
            # and
            #   # command
            hostname_command = _HOSTNAME_COMMAND_REGEX.match(line)
            if hostname_command:
                hostname = hostname_command.group("hostname")
                command = hostname_command.group("command")
                if hostname == "final":
                    # Yes, FINAL.SH is run on NIC!
                    for guest in sorted(guests):
                        commands.append(Command(guest, command, script, line_nr))
                elif hostname:
                    guest = GUEST_BY_HOSTNAME[hostname]
                    commands.append(Command(guest, command, script, line_nr))
                elif line:
                    commands.append(Command(None, f"# {command}", script, line_nr))
                else:
                    commands.append(Command(None, "#", script, line_nr))

        guests = Sorted(guests)
        logger.debug(f"commands {guests}; {scripts};{commands}")
        return (guests, commands)

    # *.sh files
    #
    # Need to match '*.sh' AFTER '*.sh'.
    guests, commands = _guest_scripts(directory, logger)
    logger.debug(f"{guests} {commands}")
    if guests:
        return (guests, commands)

    # Match experimental all.console.txt which contains the names of
    # the guests embeded as prompts as in "GUEST#"

    script = "all.console.txt"
    all_console_txt = path.join(directory, script)
    guests = Set()
    if os.path.exists(all_console_txt):
        commands = Commands()
        # read includes '\n';
        line_nr = 0
        for line in open(all_console_txt, "r"):
            line_nr += 1
            # regex matches both:
            #   <guestname># command
            # and
            #   # command
            guestname_command = _HOSTNAME_COMMAND_REGEX.match(line)
            if guestname_command:
                guestname = guestname_command.group("hostname") # see regex
                command = guestname_command.group("command")
                if guestname:
                    guest = hosts.guest_by_guestname(guestname)
                    commands.append(Command(guest, command, script, line_nr))
                    guests.add(guest)
                elif line:
                    commands.append(Command(None, f"# {command}", script, line_nr))
                else:
                    commands.append(Command(None, "#", script, line_nr))

        guests = Sorted(guests)
        logger.debug(f"commands {guests} {scripts}:\n{commands}")
        return (guests, commands)

    logger.warning(f"no scripts in {directory}")
    return (None, None)
