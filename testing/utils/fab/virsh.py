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

import subprocess
import pexpect
import sys
import time
import logging
import re
import os

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
        self._mounts = None
        self._xml = None

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
        if self._xml == None:
            status, self._xml = self.run_status_output(_VIRSH + ["dumpxml", self.name])
            if status:
                raise AssertionError("dumpxml failed: %s" % (output))
        return self._xml

    def console(self, timeout=CONSOLE_TIMEOUT):
        command = " ".join(_VIRSH + ["console", "--force", self.name])
        self.logger.debug("opening console with: %s", command)
        console = shell.Remote(command, hostname=self.host_name,
                               prefix=self.prefix)
        # Give the virsh process a chance set up its control-c
        # handler.  Otherwise something like control-c as the first
        # character sent might kill it.  If the machine is down, it
        # will get an EOF.
        if console.expect(["Connected to domain %s\r\nEscape character is \\^]" % self.name,
                           pexpect.EOF],
                          timeout=timeout):
            self.logger.debug("got EOF from console")
            console.close()
            console = None
        return console

    def _get_mounts(self, console):
        # First extract the 9p mount points from LIBVIRT.
        #
        # The code works kind of but not really like a state machine.
        # Specific lines trigger actions.
        mount_points = {}
        for line in self.dumpxml().splitlines():
            if re.compile("<filesystem type='mount' ").search(line):
                source = ""
                target = ""
                continue
            match = re.compile("<source dir='([^']*)'").search(line)
            if match:
                source = match.group(1)
                # Strip trailing "/" along with other potential quirks
                # such as the mount point being a soft link.
                source = os.path.realpath(source)
                continue
            match = re.compile("<target dir='([^']*)'").search(line)
            if match:
                target = match.group(1)
                continue
            if re.compile("<\/filesystem>").search(line):
                self.logger.debug("filesystem '%s' '%s'", target, source)
                mount_points[target] = source
                continue
        # now query the domain for its fstab, save it in regex
        # group(1); danger binary data!
        console.sendline("cat /etc/fstab")
        status, output = console.expect_prompt(rb'(.*)')
        if status:
            raise AssertionError("extracting fstab failed: %s", status)
        fstab = output.group(1).decode()
        # convert the fstab into a second map; look for NFS and 9p
        # mounts
        mounts = []
        for line in fstab.splitlines():
            self.logger.debug("line: %s", line)
            if line.startswith("#"):
                continue
            fields = line.split()
            if len(fields) < 3:
                continue
            device = fields[0]
            mount = fields[1]
            fstype = fields[2]
            if fstype == "nfs":
                self.logger.debug("NFS mount '%s''%s'", device, mount)
                device = device.split(":")[1]
                # switch to utf-8
                mounts.append((device, mount))
            elif fstype == "9p":
                if device in mount_points:
                    self.logger.debug("9p mount '%s' '%s'", device, mount)
                    device = mount_points[device]
                    mounts.append((device, mount))
                else:
                    self.logger.info("9p mount '%s' '%s' is not in domain description", device, mount)
            else:
                self.logger.debug("skipping %s mount '%s' '%s'", fstype, device, mount)

        mounts = sorted(mounts, key=lambda item: item[0], reverse=True)
        return mounts

    def guest_path(self, console, host_path):
        if self._mounts is None:
            self._mounts = self._get_mounts(console)
        # Note that REMOTE_MOUNTS is sorted in reverse order so that
        # /source/testing comes before /source.  This way the loger
        # path is matched first.
        self.logger.debug("ordered mounts %s", self._mounts);
        host_path = os.path.realpath(host_path)
        for host_directory, guest_directory in self._mounts:
            self.logger.debug("host %s guest %s path %s", host_directory, guest_directory, host_path)
            if os.path.commonprefix([host_directory, host_path]) == host_directory:
                # Found the local directory containing path that is
                # mounted on the guest; now convert that into an
                # absolute guest path.
                return guest_directory + host_path[len(host_directory):]

        raise AssertionError("the host path '%s' is not mounted on the guest %s" % (host_path, self))
