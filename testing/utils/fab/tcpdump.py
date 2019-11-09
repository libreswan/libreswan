# tcpdump driver, for libreswan
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

import re
import subprocess
from os import path

from fab import logutil


def _interfaces(domains):
    interfaces = set()
    for domain in domains:
        status, output = domain.dumpxml()
        if status:
            domain.logger.error("dumpxml failed: %s" % (output))
            continue
        bridges = re.compile(r"\<source network='[^']*' bridge='([^']*)'/\>").findall(output)
        if bridges:
            for bridge in bridges:
                interfaces.add(bridge)
            continue
        networks = re.compile(r"\<source network='([^']*)'/\>").findall(output)
        if networks:
            for network in networks:
                interfaces.add(network)
            continue
        domain.logger.error("domain has no interfaces")
    return interfaces


class Dump:

    def __init__(self, logger, domain_prefix, output_directory, domains, enable=True):
        self.enable = enable
        self.logger = logger
        self.domains = domains
        self.domain_prefix = domain_prefix
        self.output_directory = output_directory
        self.tcpdumps = []

    def __enter__(self):
        if self.enable:
            interfaces = _interfaces(self.domains)
            self.logger.info("tcpdump interfaces: %s", interfaces)
            for interface in list(interfaces):
                # strip the prefix
                _,_,log = interface.partition(self.domain_prefix)
                log = path.join(self.output_directory, log)
                command = [
                    "sudo", "tcpdump",
                    "-i", interface,
                    "-w", log + ".pcap",
                    "-s", "0", "-n", "not stp and not port 22"
                ]
                self.logger.info("tcpdump command: %s", command)
                with open(log + ".log", "w") as out:
                    t = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                         stdout=out, stderr=subprocess.STDOUT,
                                         start_new_session=True)
                    self.tcpdumps.append(t)
        self.logger.info("tcpdump processes: %s",
                         " ".join([str(t.pid) for t in self.tcpdumps]))

    def __exit__(self, type, value, traceback):
        for t in self.tcpdumps:
            kill = ["sudo", "/usr/bin/kill", str(t.pid)]
            self.logger.info("killing tcpdump with: %s", kill)
            for attempt in range(5):
                k = subprocess.Popen(kill, stdin=subprocess.DEVNULL)
                output, error = k.communicate()
                self.logger.info("%s output: %d '%s' '%s'", kill, k.returncode, output, error)
                try:
                    t.wait(timeout=1)
                    self.logger.info("exit code %d", t.returncode)
                    break
                except subprocess.TimeoutExpired:
                    self.logger.info("timedout %s", str(t.pid))
