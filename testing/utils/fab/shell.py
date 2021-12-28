# Stuff to talk to virsh, for libreswan
#
# Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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
from fab import timing

TIMEOUT = 10

# The following prompt is assumed.
# - it only displays status when it is non-zero
# - \h \u \W don't work on NetBSD
# - OpenBSD doesn't define ${HOST} or ${HOSTNAME}
PS1='[$USER@$(hostname|sed -e s/\\\\..*//) \\$(s=\\$?;p=\\${PWD##*/};echo \\${p:-/} \\${s#0})]# '

# Named groups for each part of the above
USERNAME_GROUP = "username"
HOSTNAME_GROUP = "hostname"
BASENAME_GROUP = "basename"
STATUS_GROUP = "status"
DOLLAR_GROUP = "dollar"

# Patterns for each part of the above prompt
USERNAME_PATTERN = r'[-.a-z0-9]+'
HOSTNAME_PATTERN = r'[-a-z0-9]+'
BASENAME_PATTERN = r'[-+=:,\.a-z0-9A-Z_~]+'
STATUS_PATTERN = r'| [0-9]+'
DOLLAR_PATTERN = r'[#\$]'

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

    # XXX:
    #
    # There's this new fangled thing called "bracketed paste mode"
    # which throws magic escape characters into the output stream.
    # The below will match them letting KVMSH login.  This doesn't do
    # anything for *.console.verbose.txt that will likely also be full
    # of it.
    #
    # Can't anchor this pattern to the end-of-buffer using $ as other
    # random output may appear.

    prompt = (r'(|\x1b\[\?2004h)' + # bracketed paste mode prefix!
              r'(' +
              (
                  (hostname or HOSTNAME_PATTERN)
              ) +
              r'|' +
              (
                  r'\[' +
                  r'(?P<' + USERNAME_GROUP + r'>' + (username or USERNAME_PATTERN) + r')' +
                  r'@' +
                  r'(?P<' + HOSTNAME_GROUP + r'>' + HOSTNAME_PATTERN + r')' +
                  r' ' +
                  r'(?P<' + BASENAME_GROUP + r'>' + (BASENAME_PATTERN) + r')' +
                  r'(?P<' + STATUS_GROUP + r'>'   + (STATUS_PATTERN) + r')' +
                  r'\]'
              ) +
              r')' +
              r'(?P<' + DOLLAR_GROUP + r'>'   + (dollar or DOLLAR_PATTERN)  + r')' +
              r' ')
    logger.debug("prompt '%s'", prompt)
    # byte regex
    return re.compile(prompt.encode())


def check_prompt_group(logger, match, expected, field):
    if expected:
        found = match.group(field).decode('utf-8')
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

    def __init__(self, command, logger, hostname=None, username=None):
        # Need access to HOSTNAME.
        self.logger = logger
        self.unicode_output_file = None
        self.basename = None
        self.hostname = hostname
        self.username = username
        self.prompt = compile_prompt(self.logger, hostname=hostname, username=username)
        # Create the child: configure -ve timeout parameters to act
        # like poll, and give all methods an explicit default of
        # TIMEOUT seconds; leave searchwindowsize set to the infinite
        # default so that expect patterns do not mysteriously fail.
        self.logger.debug("spawning '%s'", command)
        self.child = pexpect.spawn(command, timeout=0)
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
        self.logger.info("closing console")
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
        number = str(random.randrange(10000, 1000000))
        sync = "sync=" + number + "=cnyc"
        self.sendline("echo " + sync)
        self.expect(sync.encode() + rb'\s+' + self.prompt.pattern, timeout=timeout)

        # Fix the prompt
        self.run("expr $SHELL : '.*/sh' > /dev/null && set -o promptcmds")
        self.run("PS1=\"" + PS1 + "\"")

        # Re-sync with the prompt; the string setting the prompt
        # confuses the prompt match code.  OOPS.
        number = str(random.randrange(10000, 1000000))
        sync = "sync=" + number + "=cnyc"
        self.sendline("echo " + sync)
        self.expect(sync.encode() + rb'\s+' + self.prompt.pattern, timeout=timeout)

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
        return self.run("cd " + directory)

    def redirect_output(self, unicode_file):
        self.unicode_output_file = unicode_file
        self.logger.debug("switching output from %s to %s's buffer", self.child.logfile, unicode_file)
        self.child.logfile = unicode_file and unicode_file.buffer or None

    def append_output(self, unicode_format, *unicode_args):
        self.unicode_output_file.write(unicode_format % unicode_args)
        self.unicode_output_file.flush()

    def close_output(self):
        if self.unicode_output_file:
            self.logger.info("closing console output");
            self.unicode_output_file.close()
            self.child.logfile = None

    def sendline(self, line):
        return self.child.sendline(line)

    def drain(self):
        self.logger.debug("draining any existing output")
        if self.expect([rb'.+', pexpect.TIMEOUT], timeout=0) == 0:
            self.logger.info("discarding '%s' and re-draining", self.child.match)
            self.expect([rb'.+', pexpect.TIMEOUT], timeout=0)

    def expect(self, expect, timeout=TIMEOUT, searchwindowsize=-1):
        timer = timing.Lapsed()
        match = self.child.expect(expect, timeout=timeout,
                                  searchwindowsize=searchwindowsize)
        self.logger.debug("%s matched after %s", ascii(expect[match]), timer)
        return match

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
        if self.expect([expect + rb'\s+' + self.prompt.pattern, self.prompt],
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
