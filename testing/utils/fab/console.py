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

# Names for each of the groups in the above (used below).
#
# Note that these are STRINGS and not BYTES.  Even though any names in
# re.match(b'...') are bytes, the regex code indexes the group
# dictionary with the names converted to strings.

USERNAME_GROUP = "username"
HOSTNAME_GROUP = "hostname"
BASENAME_GROUP = "basename"
STATUS_GROUP = "status"
DOLLAR_GROUP = "dollar"

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
#
# Construct the regex as a STRING, and then convert it to BYTEs.
# The regex code indexes the group dictionary using the string
# name so this is hopefully easier?

_PROMPT_PATTERN = (r'(|\x1b\[\?2004h)' + # bracketed paste mode prefix!
                   r'(' +
                   ( # HOSTNAME#
                       r'[-a-z0-9]+'
                   ) +
                   r'|' +
                   ( # [USER@HOST DIRECTORY [STATUS]]#
                       r'\[' +
                       r'(?P<' + USERNAME_GROUP + r'>[-.a-z0-9]+)' +
                       r'@' +
                       r'(?P<' + HOSTNAME_GROUP + r'>[-a-z0-9]+)' +
                       r' ' +
                       r'(?P<' + BASENAME_GROUP + r'>[-+=:,\.a-z0-9A-Z_~]+)' +
                       r'(| (?P<' + STATUS_GROUP + r'>[0-9]+))' +
                       r'\]'
                   ) +
                   r')' +
                   r'(?P<' + DOLLAR_GROUP + r'>[#\$])' +
                   r' ').encode()

_PROMPT_REGEX = re.compile(_PROMPT_PATTERN)

def _check_prompt_group(logger, match, field, expected):
    if expected:
        found = match.group(field)
        if expected.encode() != found:
            # Throw TIMEOUT as that is what is expected and what
            # would have happened.
            raise pexpect.TIMEOUT("incorrect prompt, field '%s' should be '%s but was '%s'" \
                                  % (field, expected, found))


def _check_prompt(logger, match, hostname=None, username=None, basename=None, dollar=None):
    """Match wild-card  of the prompt pattern; return status"""

    logger.debug("match %s contains %s", match, match.groupdict())
    _check_prompt_group(logger, match, HOSTNAME_GROUP, hostname)
    _check_prompt_group(logger, match, USERNAME_GROUP, username)
    _check_prompt_group(logger, match, BASENAME_GROUP, basename)
    _check_prompt_group(logger, match, DOLLAR_GROUP, dollar)
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
        self.prompt = _PROMPT_REGEX
        # Create the child: configure -ve timeout parameters to act
        # like poll, and give all methods an explicit default of
        # TIMEOUT seconds; leave searchwindowsize set to the infinite
        # default so that expect patterns do not mysteriously fail.
        self.logger.debug("spawning '%s'", " ".join(command))
        self.child = pexpect.spawn(command[0], args=command[1:], timeout=0)
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

        # Sync with the remote end by matching a known and unique
        # pattern.  Strictly match PATTERN+PROMPT so that earlier
        # prompts that might also be lurking in the output are
        # discarded.
        number = str(random.randrange(10000, 1000000))
        sync = "sync=" + number + "=cnyc"
        self.sendline("echo " + sync)
        self.expect(sync.encode() + rb'\s+' + self.prompt.pattern, timeout=timeout)

        # Set the PTY inside the VM to no-echo
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
        status = _check_prompt(self.logger, self.child.match,
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

    def expect_prompt(self, expect, timeout=TIMEOUT, searchwindowsize=-1):
        """Like expect but also match the prompt

        In addition to matching EXPECT+"\s+"+PROMPT, and to speed up
        error detection, just PROMPT is also matched.  The latter is
        treated as if a timeout occurred.  If things are not kept in
        sync, this will match an earlier prompt.  The idea is found in
        DEJAGNU based tools.

        Returns both the exit status and the re.match

        """

        self.logger.debug("expect '%s' and prompt", expect.decode('ascii'))
        if self.expect([expect + rb'\s+' + self.prompt.pattern, self.prompt],
                       timeout=timeout, searchwindowsize=searchwindowsize):
            self.logger.debug("only matched prompt")
            raise pexpect.TIMEOUT("pattern %s not found" % expect)
        status = _check_prompt(self.logger, self.child.match,
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
