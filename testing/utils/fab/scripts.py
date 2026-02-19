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
    scripts = Set()
    for script in glob(path.join(directory, "*.sh")):
        if not path.isfile(script):
            continue
        # Add more filter-outs
        scripts.add(path.basename(script))
    return scripts

def _add_script_commands(script, commands, directory, guest):
    for line in open(os.path.join(directory, script), "r"):
        # toss blank lines and trailing '\n'
        line = line.strip()
        if line:
            commands.append(Command(guest, line, script))

def _add_script(script, commands, scripts, directory,
                script_guests, test_guests):
    if script_guests and script in scripts:
        scripts.remove(script)
        for guest in script_guests:
            test_guests.add(guest)
            _add_script_commands(script, commands, directory, guest)

def _guest_scripts(directory, logger):
    """Return a list of {guestname:, path:} to run"""

    scripts = _scripts(directory)
    logger.debug(f"scripts: {scripts}");
    test_guests = hosts.Set()

    # Compatibility hack:
    #
    # Find the commands matching <linux-guest>init.sh and within that
    # force LINUX_GUESTS is ordered with "nic" then "east" first.

    init_commands = Commands()
    for guest in hosts.LINUX_GUESTS:
        _add_script(guest.host.name+"init.sh", init_commands,
                    scripts, directory,
                    [guest], test_guests)
    logger.debug(f"init commands {test_guests} {scripts}:\n{init_commands}")

    # Compatibility hack:
    #
    # Find the commands matching <linux-guest>run.sh.  These will be
    # run second.

    run_commands = Commands()
    for guest in hosts.LINUX_GUESTS:
        _add_script(guest.host.name+"run.sh", run_commands,
                    scripts, directory,
                    [guest], test_guests)
    logger.debug(f"run commands {test_guests} {scripts}:\n{run_commands}")

    # Look for scripts containing host names.
    #
    # Preserve the order that the host names appear in the file name.
    # For instance, the script 99-west-east.sh would be run on west
    # then east.

    ordered_commands = Commands()
    for script in sorted(scripts):
        _add_script(script, ordered_commands,
                    scripts, directory,
                    hosts.guests_by_filename(script),
                    test_guests)
    logger.debug(f"ordered commands {test_guests} {scripts}:\n{ordered_commands}")

    # Part compatibility hack.
    #
    # part new behaviour: form a list of scripts matching final.sh.
    # These will be run last.

    final_commands = Commands()
    _add_script("final.sh", final_commands,
                scripts, directory,
                sorted(test_guests), test_guests)
    logger.debug(f"final commands {test_guests} {scripts}:\n{final_commands}")

    all_commands = Commands()
    all_commands.extend(init_commands)
    all_commands.extend(run_commands)
    all_commands.extend(ordered_commands)
    all_commands.extend(final_commands)

    logger.debug(f"all commands {test_guests} {scripts}:\n{all_commands}")
    return all_commands

# for line in open("r").line includes; when <guest> is blank, a
# comment is assumed.

_HOSTNAME_COMMAND_REGEX = re.compile(r'^(?P<hostname>[a-z]*)# ?(?P<command>.*)[\n]$')

def commands(directory, logger):

    # match *.sh first
    commands = _guest_scripts(directory, logger)
    if commands:
        return commands

    # Match experimental all.console.txt which contains the names of
    # the domains embeded as prompts as in "DOMAIN#"

    script = "all.console.txt"
    all = path.join(directory, script)
    if os.path.exists(all):
        commands = Commands()
        # read includes '\n';
        for line in open(all, "r"):
            # regex matches both:
            #   <guestname># command
            # and
            #   # command
            guestname_command = _HOSTNAME_COMMAND_REGEX.match(line)
            if guestname_command:
                guestname = guestname_command.group("hostname") # see regex
                command = guestname_command.group("command")
                if guestname:
                    commands.append(Command(hosts.guest_by_guestname(guestname), command, script))
                elif line:
                    commands.append(Command(None, "# "+command, script))
                else:
                    commands.append(Command(None, "#", script))
        return commands

    # Match experimental *DOMAIN*.in, or *DOMAIN*.console.txt, which
    # contains prompts using the domain's host names.
    #
    # .in is known to work .console.txt is experimental.

    for match in ("*.in", "*.console.txt"):

        scripts = glob(path.join(directory, match))
        if scripts:

            # figure out the host->domain map
            domains = hosts.Set()
            for script in scripts:
                guests = hosts.guests_by_filename(script);
                domains.update(guests)
                logger.debug(f"script {script} guests: {guests}")
            domains = sorted(domains)
            DOMAIN_BY_HOSTNAME = hosts.Dict()
            for domain in domains:
                DOMAIN_BY_HOSTNAME[domain.host.name] = domain
            logger.debug(f"DOMAIN_BY_HOSTNAME: {DOMAIN_BY_HOSTNAME}")

            commands = Commands()
            for script in scripts:
                if not path.isfile(script):
                    continue
                logger.debug(f"script: {script}")
                for line in open(script, "r"):
                    logger.debug(f"{line[0:-1]}")
                    # regex matches both:
                    #   <hostname># command
                    # and
                    #   # command
                    hostname_command = _HOSTNAME_COMMAND_REGEX.match(line)
                    if hostname_command:
                        hostname = hostname_command.group("hostname")
                        command = hostname_command.group("command")
                        if hostname:
                            domain = DOMAIN_BY_HOSTNAME[hostname]
                            commands.append(Command(domain, command, script))
                        elif line:
                            commands.append(Command(None, "# "+command, script))
                        else:
                            commands.append(Command(None, "#", script))
            return commands

    logger.warning(f"no scripts in {directory}")
    return Commands()
