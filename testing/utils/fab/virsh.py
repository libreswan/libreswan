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

import time
import subprocess
import pexpect
import sys
import time
import logging
import re
import os

from fab import console
from fab import logutil
from fab import timing

class STATE:
    RUNNING = "running"
    IDLE = "idle"
    PAUSED = "paused"
    IN_SHUTDOWN = "in shutdown"
    SHUT_OFF = "shut off"
    CRASHED = "crashed"
    DYING = "dying"
    PMSUSPENDED = "pmsuspended"

_VIRSH = ["sudo", "virsh", "--connect", "qemu:///system"]

START_TIMEOUT = 90
# Can be anything as it either matches immediately or dies with EOF.
CONSOLE_TIMEOUT = 20
SHUTDOWN_TIMEOUT = 30
DESTROY_TIMEOUT = 20
TIMEOUT = 10

class Domain:

    def __init__(self, logger, name=None, prefix=None, guest=None):
        # Use the term "domain" just like virsh
        self.name = name or prefix+guest.name
        self.guest = guest
        self.logger = logger
        self.debug_handler = None
        self.logger.debug("domain created")
        self._mounts = None
        self._xml = None
        # ._console is three state: None when state unknown; False
        # when shutdown (by us); else the console.
        self._console = None

    def __str__(self):
        return "domain " + self.name

    def nest(self, logger, prefix):
        self.logger = logger.nest(prefix + self.name)
        if self._console:
            self._console.logger = self.logger
        return self.logger

    def _run_status_output(self, command, verbose=False):
        if verbose:
            self.logger.info("running: %s", command)
        else:
            self.logger.debug("running: %s", command)
        # 3.5 has subprocess.run
        process = subprocess.Popen(command,
                                   stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        stdout, stderr = process.communicate()
        status = process.returncode
        output = stdout.decode('utf-8').strip()
        if status:
            self.logger.debug("virsh exited with unexpected status code %s\n%s",
                              status, output)
        else:
            self.logger.debug("output: %s", output)
        return status, output

    def state(self):
        status, output = self._run_status_output(_VIRSH + ["domstate", self.name])
        if status:
            return None
        else:
            return output

    def _shutdown(self):
        self._run_status_output(_VIRSH + ["shutdown", self.name])

    def shutdown(self):
        """Use the console to detect the shutdown - if/when the domain stops
        it will exit giving an EOF.

        """

        if self._console is False:
            self.logger.error("domain already shutdown")
            return True

        if self._console is None:
            if not self._open_console():
                self.logger.error("domain already shutdown")
                return True

        self.logger.info("waiting %d seconds for domain to shutdown", SHUTDOWN_TIMEOUT)
        lapsed_time = timing.Lapsed()
        self._shutdown()
        if self._console.expect([pexpect.EOF, pexpect.TIMEOUT],
                                timeout=SHUTDOWN_TIMEOUT) == 0:
            self.logger.info("got EOF; domain shutdown after %s", lapsed_time)
            self._console = False
            self.logger.info("domain state is: %s", self.state())
            return True
        self.logger.error("timeout shutting down domain")
        return self.destroy()

    def _destroy(self):
        return self._run_status_output(_VIRSH + ["destroy", self.name])

    def destroy(self):
        """Use the console to detect a destroyed domain - if/when the domain
        stops it will exit giving an EOF.

        """

        console = self.console()
        if not console:
            self.logger.error("domain already destroyed")
            return True

        self.logger.info("waiting %d seconds for domain to be destroyed", DESTROY_TIMEOUT)
        lapsed_time = timing.Lapsed()
        self._destroy()
        if console.expect([pexpect.EOF, pexpect.TIMEOUT],
                          timeout=DESTROY_TIMEOUT) == 0:
            self.logger.info("domain destroyed after %s", lapsed_time)
            self._console = None
            return True

        self.logger.error("timeout destroying domain, giving up")
        self._console = None
        return False

    def reboot(self):
        return self._run_status_output(_VIRSH + ["reboot", self.name])

    def start(self):
        # A shutdown domain can linger for a bit
        shutdown_timeout = START_TIMEOUT
        while self.state() == STATE.IN_SHUTDOWN and shutdown_timeout > 0:
            self.logger.info("waiting for domain to finish shutting down")
            time.sleep(1)
            shutdown_timeout = shutdown_timeout - 1;

        command = _VIRSH + ["start", self.name, "--console"]
        self.logger.info("spawning: %s", " ".join(command))
        self._console = console.Console(command, self.logger,
                                        host_name=self.guest and self.guest.host.name)
        match = self._console.expect([("Domain '%s' started\r\n" +
                                       "Connected to domain '%s'\r\n" +
                                       "Escape character is \\^] \(Ctrl \+ ]\)\r\n") % (self.name, self.name),
                                      pexpect.TIMEOUT,
                                      pexpect.EOF],
                                     timeout=START_TIMEOUT)
        if match == 0: #success
            self.logger.info("domain started");
            return self._console

        if match == 1: #TIMEOUT
            if self._open_console(): #could re-timeout
                return self._console

        # already tried and failed
        self._console = False
        raise pexpect.EOF("failed to start domain %s" % self.name)

    def dumpxml(self):
        if self._xml == None:
            status, self._xml = self._run_status_output(_VIRSH + ["dumpxml", self.name])
            if status:
                raise AssertionError("dumpxml failed: %s" % (output))
        return self._xml

    def _open_console(self):
        # self._console is None
        command = _VIRSH + ["console", "--force", self.name]
        self.logger.info("spawning: %s", " ".join(command))
        self._console = console.Console(command, self.logger,
                                        host_name=self.guest and self.guest.host.name)
        # Give the virsh process a chance set up its control-c
        # handler.  Otherwise something like control-c as the first
        # character sent might kill it.  If the machine is down, it
        # will get an EOF.
        if self._console.expect([pexpect.EOF,
                                 # earlier
                                 "Connected to domain %s\r\nEscape character is \\^]" % self.name,
                                 # libvirt >= 7.0
                                 "Connected to domain '%s'\r\nEscape character is \\^] \(Ctrl \+ ]\)\r\n" % self.name
                                 ],
                                timeout=CONSOLE_TIMEOUT) > 0:
            self.logger.debug("console attached");
            return self._console
        self.logger.info("got EOF from console")
        self._console.close()
        self._console = False
        return None

    def console(self):
        if self._console:
            self.logger.info("console already open")
            return self._console
        if self._console is False:
            self.logger.info("console already failed")
            return self._console
        return self._open_console()

    def close(self):
        if self._console:
            self._console.close()
        self._console = None # not False

