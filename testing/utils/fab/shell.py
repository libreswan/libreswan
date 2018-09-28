# Stuff to talk to virsh, for libreswan
#
# Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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
import random
import pexpect
import re
from fab import logutil

TIMEOUT = 10

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
BASENAME_PATTERN = "[-+=:,\.a-z0-9A-Z_~]+"
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
            raise pexpect.TIMEOUT("incorrect prompt, field '%s' should be '%s but was '%s'" \
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

    def __init__(self, command, hostname=None, username=None, prefix=""):
        # Need access to HOSTNAME.
        self.logger = logutil.getLogger(prefix, __name__, hostname)
        self.basename = None
        self.hostname = hostname
        self.username = username
        self.prompt = compile_prompt(self.logger, hostname=hostname, username=username)
        # Create the child: configure -ve timeout parameters to act
        # like poll, and give all methods an explicit default of
        # TIMEOUT seconds; leave searchwindowsize set to the infinte
        # default so that expect patterns do not mysteriously fail.
        self.logger.debug("spawning '%s'", command)
        self.child = pexpect.spawnu(command, timeout=0)
        #This crashes inside of pexpect!
        #self.logger.debug("child is '%s'", self.child)
        # route low level output to the logger
        self.child.logfile_read = Debug(self.logger, "read <<%s>>>")
        self.child.logfile_send = Debug(self.logger, "send <<%s>>>")

    def close(self):
        """Close the console

        The intent is to close the PTY.  Since COMMAND is (probably)
        running as root, any attempt by .close() to kill the process
        using a signal will fail.  Consequently, the caller should
        first shutdown the process, and then call close (hint: use
        .sendcontrol("]")

        """
        self.child.close()

    def sync(self, hostname=None, username=None, timeout=TIMEOUT):
        self.hostname = hostname or self.hostname
        self.username = username or self.username
        # Update the expected prompt
        self.hostname = hostname
        self.username = username
        self.prompt = compile_prompt(self.logger, hostname=self.hostname, username=self.username)
        # Sync with the remote end by matching a known and unique
        # pattern.  Strictly match PATTERN+PROMPT so that earlier
        # prompts that might also be lurking in the output are
        # discarded.
        number = str(random.randrange(1000000, 100000000))
        sync = "sync=" + number + "=cnyc"
        self.sendline("echo " + sync)
        self.expect(sync + "\s+" + self.prompt.pattern, timeout=timeout)
        # Fix the prompt
        self.run("PS1='" + PS1 + "'")
        # Set noecho the PTY inside the VM (not pexpect's PTY).
        self.run("export TERM=dumb; unset LS_COLORS; stty sane -echo -onlcr")

    def stty_sane(self, term="dumb", rows=24, columns=80):
        # Get the PTY inside the VM (not pexpect's PTY) into normal
        # mode.
        stty = ("unset LS_COLORS; export TERM=%s; stty sane rows %s columns %s"
                % (term, rows, columns))
        self.run(stty)

    def run(self, command, timeout=TIMEOUT, searchwindowsize=-1):
        self.logger.debug("run '%s' expecting prompt", command)
        self.child.sendline(command)
        # This can throw a pexpect.TIMEOUT or pexpect.EOF exception
        self.child.expect(self.prompt, timeout=timeout, \
                          searchwindowsize=searchwindowsize)
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

    def drain(self):
        self.logger.debug("draining any existing output")
        if self.expect([r'.+', pexpect.TIMEOUT], timeout=0) == 0:
            self.logger.info("discarding '%s' and re-draining", self.child.match)
            self.expect([r'.+', pexpect.TIMEOUT], timeout=0)

    def expect(self, expect, timeout=TIMEOUT, searchwindowsize=-1):
        return self.child.expect(expect, timeout=timeout,
                                 searchwindowsize=searchwindowsize)

    def expect_exact(self, expect, timeout=TIMEOUT, searchwindowsize=-1):
        return self.child.expect_exact(expect, timeout=timeout,
                                       searchwindowsize=searchwindowsize)

    def sendcontrol(self, control):
        return self.child.sendcontrol(control)

    def expect_prompt(self, expect, timeout=TIMEOUT, searchwindowsize=-1):
        """Like expect but also match the prompt

        In addition to matching EXPECT+"\s+"+PROMPT, and to speed up
        error detection, just PROMPT is also matched.  The latter is
        treated as if a timeout occurred.  If things are not kept in
        sync, this will match an earlier prompt.  The idea is found in
        DEJAGNU based tools.

        Returns both the exit status and the re.match

        """

        self.logger.debug("expect '%s' and prompt", expect)
        if self.expect([expect + "\s+" + self.prompt.pattern, self.prompt],
                       timeout=timeout, searchwindowsize=searchwindowsize):
            self.logger.debug("only matched prompt")
            raise pexpect.TIMEOUT("pattern %s not found" % expect)
        status = check_prompt(self.logger, self.child.match,
                              basename=self.basename)
        self.logger.debug("status %s match %s", status, self.child.match)
        return status, self.child.match

    def sendcontrol(self, control):
        return self.child.sendcontrol(control)

    def sendintr(self):
        return self.child.sendintr()

    def interact(self):
        self.logger.debug("entering interactive mode")
        return self.child.interact()
