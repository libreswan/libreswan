# Stuff to talk to virsh, for libreswan
#
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

import os
import random
import pexpect
import re
from fab import logutil

TIMEOUT = 10
SEARCH_WINDOW_SIZE = 100

# The following prompt is assumed.  It only displays status when it is
# non-zero:
PS1='[\\u@\\h \\W$(x=$? ; test $x -ne 0 && echo " $x")]\\$ '
#PS1='[\\u@\\h \\W $?]\\$ '

# Named groups for each part of the above
USERNAME_GROUP = "username"
HOSTNAME_GROUP = "hostname"
BASENAME_GROUP = "basename"
STATUS_GROUP = "status"
DOLLAR_GROUP = "dollar"

# Patterns for each part of the above prompt
USERNAME_PATTERN = "[-\.a-z0-9]+"
HOSTNAME_PATTERN = "[-a-z0-9]+"
BASENAME_PATTERN = "[-\.a-z0-9A-Z_~]+"
STATUS_PATTERN = "| [0-9]+"
DOLLAR_PATTERN = "[#\$]"

def compile_prompt(logger, username=None, hostname=None):
    """Create a regex that matches PS1.

    Known fields get hard wired.  Unknown or variable fields match
    wild-card patterns.

    """

    # Fix up dollar when username known
    dollar = None
    if username:
        if username == "root":
            dollar = "#"
        else:
            dollar = "$"
    prompt = "\[(?P<" + USERNAME_GROUP + ">" + (username or USERNAME_PATTERN) + ")" + \
             "@(?P<" + HOSTNAME_GROUP + ">"  + (hostname or HOSTNAME_PATTERN) + ")" + \
             " (?P<" + BASENAME_GROUP + ">"  + (BASENAME_PATTERN) + ")" + \
             "(?P<" + STATUS_GROUP + ">" + (STATUS_PATTERN) + ")" + \
             "\](?P<" + DOLLAR_GROUP + ">"  + (dollar or DOLLAR_PATTERN)  + ")" + \
             " "
    logger.debug("prompt '%s'", prompt)
    return re.compile(prompt)

def check_prompt_group(logger, match, expected, field):
    if expected:
        found = match.group(field)
        logger.debug("prompt field: '%s' expected: '%s' found: '%s'", field, expected, found)
        if expected != found:
            # Throw TIMEOUT as that is what is expected and what
            # would have happened.
            pexpect.TIMEOUT("incorrect prompt, field '%s' should be '%s but was '%s'" \
                            % (field, expected, found))

def check_prompt(logger, match, hostname=None, username=None, basename=None, dollar=None):
    """Match wild-card  of the prompt pattern; return status""" 

    logger.debug("match %s contains %s", match, match.groupdict())
    check_prompt_group(logger, match, hostname, HOSTNAME_GROUP)
    check_prompt_group(logger, match, username, USERNAME_GROUP)
    check_prompt_group(logger, match, basename, BASENAME_GROUP)
    check_prompt_group(logger, match, dollar, DOLLAR_GROUP)
    # If there's no status, return None, not empty.
    status = match.group(STATUS_GROUP)
    if status:
        status = int(status)
    else:
        status = None
    logger.debug("exit code '%s'", status)
    return status

# This file-like class passes all writes on to the LOGGER at DEBUG.
# It is is used to direct pexpect's .logfile_read and .logfile_send
# files into the logging system.

class Debug:

    def __init__(self, logger, message):
        self.logger = logger
        self.message = message

    def close(self):
        pass

    def write(self, text):
        self.logger.debug(self.message, ascii(text))

    def flush(self):
        pass

class Remote:

    def __init__(self, command, hostname=None, username=None, logger=None):
        # Need access to HOSTNAME.
        self.logger = logger or logutil.getLogger(__name__, hostname)
        self.basename = None
        self.hostname = hostname
        self.username = username
        self.prompt = compile_prompt(self.logger, hostname=hostname, username=username)
        # Create the child; configure -ve timeout parameter to act
        # like poll.
        self.logger.debug("spawning '%s'", command)
        self.child = pexpect.spawnu(command)
        #This crashes inside of pexpect!
        #self.logger.debug("child is '%s'", self.child)
        self.child.timeout = 0
        # route low level output to the logger
        self.child.logfile_read = Debug(self.logger, "read <<%s>>>")
        self.child.logfile_send = Debug(self.logger, "send <<%s>>>")

    def sync(self, hostname=None, username=None):
        self.hostname = hostname or self.hostname
        self.username = username or self.username
        # Update the expected prompt
        self.hostname = hostname
        self.username = username
        self.prompt = compile_prompt(self.logger, hostname=self.hostname, username=self.username)
        # force a prompt sync using a random number
        number = str(random.randrange(1000000, 100000000))
        self.run("echo sync=" + number + "=sync", expect="sync=" + number + "=sync\\s*")
        # Fix the prompt
        self.run("PS1='" + PS1 + "'")
        # Set noecho the PTY inside the VM (not pexpect's PTY).
        self.run("export TERM=dumb; unset LS_COLORS; stty sane -echo -onlcr")

    def stty_sane(self):
        # Get the PTY inside the VM (not pexpect's PTY) into normal
        # mode.
        self.run('export TERM=dumb; unset LS_COLORS; stty sane')

    def run(self, command, expect=None, timeout=TIMEOUT):
        self.logger.debug("shell send '%s'", command)
        self.child.sendline(command)
        # This can throw a pexpect.TIMEOUT or pexpect.EOF exception
        match = self.prompt
        if expect:
            match = "%s%s" % (expect, self.prompt.pattern)
        self.logger.debug("shell match '%s'", match)
        self.child.expect(match, timeout=timeout, \
                          searchwindowsize=SEARCH_WINDOW_SIZE)
        status = check_prompt(self.logger, self.child.match,
                              basename=self.basename)
        self.logger.debug("run exit status %s", status)
        return status

    def chdir(self, directory):
        self.basename = os.path.basename(directory)
        return self.run("cd %s" % directory)

    def output(self, logfile=None):
        self.logger.debug("switching output from %s to %s", self.child.logfile, logfile)
        logfile, self.child.logfile = self.child.logfile, logfile
        return logfile

    def sendline(self, line):
        return self.child.sendline(line)

    def expect(self, expected, timeout=None):
        return self.child.expect(expected, timeout=timeout)

    def interact(self):
        self.logger.debug("entering interactive mode")
        return self.child.interact()
