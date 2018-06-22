# Stuff to talk to virsh, for libreswan
#
# Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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

import subprocess
import pexpect
import sys
import time
import logging

from fab import shell
from fab import logutil

# Can be anything as it either matches immediately or dies with EOF.
CONSOLE_TIMEOUT = 30

class STATE:
    RUNNING = "running"
    IDLE = "idle"
    PAUSED = "paused"
    SHUTDOWN = "shutdown"
    SHUT_OFF = "shut off"
    CRASHED = "crashed"
    DYING = "dying"
    PMSUSPENDED = "pmsuspended"

_VIRSH = ["sudo", "virsh", "--connect", "qemu:///system"]

class Domain:

    def __init__(self, host_name, domain_prefix="", domain_name=None):
        # Use the term "domain" just like virsh
        self.prefix = domain_prefix
        self.name = domain_name or (domain_prefix + host_name)
        self.host_name = host_name
        self.virsh_console = None
        # Logger?
        self.logger = logutil.getLogger(domain_prefix, __name__, host_name)
        self.debug_handler = None
        self.logger.debug("domain created")

    def __str__(self):
        return "domain " + self.name

    def run_status_output(self, command):
        self.logger.debug("running: %s", command)
        # 3.5 has subprocess.run
        process = subprocess.Popen(command,
                                   stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        stdout, stderr = process.communicate()
        status = process.returncode
        output = stdout.decode("utf-8").strip()
        if status:
            self.logger.debug("virsh exited with unexpected status code %s\n%s",
                              status, output)
        else:
            self.logger.debug("output: %s", output)
        return status, output

    def state(self):
        status, output = self.run_status_output(_VIRSH + ["domstate", self.name])
        if status:
            return None
        else:
            return output

    def shutdown(self):
        return self.run_status_output(_VIRSH + ["shutdown", self.name])

    def reboot(self):
        return self.run_status_output(_VIRSH + ["reboot", self.name])

    def reset(self):
        return self.run_status_output(_VIRSH + ["reset", self.name])

    def destroy(self):
        return self.run_status_output(_VIRSH + ["destroy", self.name])

    def start(self):
        return self.run_status_output(_VIRSH + ["start", self.name])

    def suspend(self):
        return self.run_status_output(_VIRSH + ["suspend", self.name])

    def resume(self):
        return self.run_status_output(_VIRSH + ["resume", self.name])

    def dumpxml(self):
        return self.run_status_output(_VIRSH + ["dumpxml", self.name])

    def console(self, timeout=CONSOLE_TIMEOUT):
        command = " ".join(_VIRSH + ["console", "--force", self.name])
        self.logger.debug("opening console with: %s", command)
        console = shell.Remote(command, hostname=self.host_name,
                               prefix=self.prefix)
        # Give the virsh process a chance set up its control-c
        # handler.  Otherwise something like control-c as the first
        # character sent might kill it.  If the machine is down, it
        # will get an EOF.
        if console.expect(["Connected to domain %s\r\nEscape character is \\^]\r\n" % self.name,
                           pexpect.EOF],
                          timeout=timeout):
            self.logger.debug("got EOF from console")
            console.close()
            console = None
        return console
