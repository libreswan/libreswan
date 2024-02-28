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

# This file-like class passes all writes on to the LOGGER at DEBUG.
# It is is used to direct pexpect's .logfile_read and .logfile_send
# files into the logging system.

class _Debug:

    def __init__(self, logger, message):
        self.logger = logger
        self.message = message

    def close(self):
        pass

    def write(self, text):
        self.logger.debug(self.message, ascii(text))

    def flush(self):
        pass

class _Redirect:

    def __init__(self, files):
        self.files = files

    def close(self):
        pass

    def write(self, text):
        for f in self.files:
            f.buffer.write(text)

    def flush(self):
        for f in self.files:
            f.flush()


class Console(pexpect.spawn):

    def __init__(self, command, logger, host_name=None):
        # Create the child.
        logger.debug("spawning '%s'", " ".join(command))
        pexpect.spawn.__init__(self, command[0], args=command[1:], timeout=TIMEOUT)
        self.logger = logger
        self.unicode_output_files = []
        self._basename = None
        self._host_name = host_name
        self.prompt = _PROMPT_REGEX
        #This crashes inside of pexpect!
        #self.logger.debug("child is '%s'", self.child)
        # route low level output to the logger
        self.logfile_read = _Debug(self.logger, "read <<%s>>>")
        self.logfile_send = _Debug(self.logger, "send <<%s>>>")

    def _check_prompt(self):
        """Match wild-card  of the prompt pattern; return status"""

        self.logger.debug("match %s contains %s", self.match, self.match.groupdict())
        # If basename is known, make certain it doesn't change.
        # Catches scripts changing directory.
        _check_prompt_group(self.logger, self.match, HOSTNAME_GROUP, self._host_name)
        _check_prompt_group(self.logger, self.match, BASENAME_GROUP, self._basename)
        # If there's no status, return None, not empty.
        status = self.match.group(STATUS_GROUP)
        if status:
            status = int(status)
        else:
            status = None
        self.logger.debug("exit code '%s'", status)
        return status

    def run(self, command, timeout=TIMEOUT):
        self.logger.debug("run '%s' expecting prompt", command)
        self.sendline(command)
        # This can throw a pexpect.TIMEOUT or pexpect.EOF exception
        self.expect(self.prompt, timeout=timeout)
        status = self._check_prompt()
        self.logger.debug("run exit status %s", status)
        return status

    def chdir(self, directory):
        # save directory so run() can verify it
        self._basename = os.path.basename(directory)
        if self.run("cd " + directory):
            # i.e., non-zero exit code
            raise Exception("'%s' failed", directory)

    def redirect_output(self, unicode_file):
        if unicode_file:
            self.unicode_output_files.append(unicode_file)
            self.logger.debug("switching output from %s to %s's buffer",
                              self.logfile, unicode_file)
            self.logfile = _Redirect(self.unicode_output_files)
        else:
            self.unicode_output_files = []
            self.logfile = None

    def drain(self):
        self.logger.debug("draining any existing output")
        if self.expect([rb'.+', pexpect.TIMEOUT], timeout=0) == 0:
            self.logger.info("discarding '%s' and re-draining", self.match)
            self.expect([rb'.+', pexpect.TIMEOUT], timeout=0)
