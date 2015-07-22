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

import re
import os
import logging
import pexpect
import time
from fab import virsh
from fab import shell

MOUNTS = {}

def mounts(domain):
    """Return a table of 9p mounts for the given domain"""
    # maintain a local cache
    if domain in MOUNTS:
        domain.logger.debug("using mounts from cache")
        return MOUNTS[domain]
    mounts = {}
    MOUNTS[domain] = mounts
    status, output = domain.dumpxml()
    if status:
        # XXX: Throw an exception?
        return mounts
    for line in output.splitlines():
        if re.compile("<filesystem type='mount' ").search(line):
            source = ""
            target = ""
            continue
        match = re.compile("<source dir='([^']*)'").search(line)
        if match:
            source = match.group(1)
            continue
        match = re.compile("<target dir='([^']*)'").search(line)
        if match:
            target = match.group(1)
            continue
        if re.compile("<\/filesystem>").search(line):
            domain.logger.debug("filesystem target '%s' source '%s'", target, source)
            mounts[target] = source
            continue
    return mounts

FSTABS = {}

def mount_point(domain, console, device):
    """Find the mount-point for device"""
    if not domain in FSTABS:
        FSTABS[domain] = {}
    fstab = FSTABS[domain]
    if device in fstab:
        mount= fstab[device]
        domain.logger.debug("using fstab entry for %s (%s) from cache", device, mount)
        return mount;
    console.sendline("awk '$1==\"" + device + "\" { print $2 }' < /etc/fstab")
    status, match = console.expect_prompt("(/\S+)")
    mount = match.group(1)
    fstab[device] = mount
    domain.logger.debug("fstab has device '%s' mounted on '%s'", device, mount)
    return mount

def directory(domain, console, directory, default=None):
    for target, source in mounts(domain).items():
        if os.path.commonprefix([source, directory]) == source:
            # found a suitable mount point, now find were it is
            # mounted on the remote machine.
            root = mount_point(domain, console, target)
            return root + directory[len(source):]
    return default

# Bring a booting machine up to point where key services have started.
#
# The service that handles "virsh shutdown" needs to be running as
# otherwise a quick shutdown after a boot will go no where.  On the
# other hand, there is no point in having a painfully long wait for
# all services to start and the login: prompt to appear.
#
# Note: It must not match anything from GRUB.  Feeding control-c and
# return (from a login attempt) to GRUB can result in weird and
# puzzling behaviour such as booting the wrong kernel.

STARTUP_TIMEOUT = 30
SHUTDOWN_TIMEOUT = 20

def _startup(domain, console, timeout=STARTUP_TIMEOUT):
    expected = "Started Login Service"
    # XXX: While len(expected) should technically be sufficient, that
    # isn't clear without looking at sources.  Instead just "double,
    # and then double again".
    console.expect(expected, timeout=timeout,
                   searchwindowsize=(len(expected)*4))
    domain.logger.info("domain started")

# Assuming the machine is booted, try to log-in.

def _login(domain, console, username, password,
           login_timeout, password_timeout, shell_timeout):

    domain.logger.info("attempting to log in; timeout: %ss password timeout: %ss shell timeout: %ss",
                       login_timeout, password_timeout, shell_timeout)
    domain.logger.debug("console prompt: %s", console.prompt.pattern)

    # Heuristic for figuring out the search window size.  Assume, in
    # the worst case, the other end contains the entire current
    # directory in the prompt.  The number is then "doubled, and then
    # doubled again".
    searchwindowsize = max(100, (len(os.getcwd()) + len(console.prompt.pattern) * 4))
    domain.logger.debug("using search window size of %s", searchwindowsize)

    domain.logger.debug("sending control-c+carriage return, waiting %s seconds for login or shell prompt", login_timeout)
    console.sendintr()
    console.sendline("")
    if console.expect(["login: ", console.prompt], timeout=login_timeout,
                      searchwindowsize=searchwindowsize):
        # shell prompt
        domain.logger.info("we're in! Someone forgot to log out ...")
        return

    domain.logger.debug("sending username '%s' waiting %s seconds for password or shell prompt", \
                        username, password_timeout)
    console.sendline(username)
    if console.expect(["Password: ", console.prompt], timeout=password_timeout,
                      searchwindowsize=searchwindowsize):
        # shell prompt
        domain.logger.info("we're in! No password ...")
        return

    domain.logger.debug("sending password '%s', waiting %s seconds for shell prompt",
                        password, shell_timeout)
    console.sendline(password)
    console.expect(console.prompt, timeout=shell_timeout)
    domain.logger.info("we're in!")

LOGIN_TIMEOUT = 60
PASSWORD_TIMEOUT = 5
SHELL_TIMEOUT = 5

# The machine is assumed to be booted.

def login(domain, console,
          username="root", password="swan",
          startup_timeout=STARTUP_TIMEOUT,
          login_timeout=LOGIN_TIMEOUT,
          password_timeout=PASSWORD_TIMEOUT,
          shell_timeout=SHELL_TIMEOUT):
    if not console:
        domain.logger.error("domain not running")
        return None
    # try to login
    _login(domain, console, username=username, password=password,
           login_timeout=login_timeout,
           password_timeout=password_timeout,
           shell_timeout=shell_timeout)
    console.sync()

def start(domain, startup_timeout=STARTUP_TIMEOUT):
    domain.logger.info("starting domain")
    # Bring the machine up from scratch.
    end_time = time.time() + startup_timeout
    # Do not call this when the console is functional!
    console = domain.console()
    if console:
        raise pexpect.TIMEOUT("console should not be open")
    first_attempt = True
    while console == None:
        if time.time() > end_time:
            pexpect.TIMEOUT("Trying to get a console")
        status, output = domain.start()
        if status and first_attempt:
            # The first attempt at starting the domain _must_ succeed.
            # Failing is a sign that the domain was running.  Further
            # attempts might fail as things get racey.
            raise pexpect.TIMEOUT("failed to start domain: %s" % output)
        time.sleep(1)
        # try opening the console again
        console = domain.console()
        first_attempt = False
    domain.logger.debug("got console")
    # Now wait for it to be usable
    _startup(domain, console, timeout=(end_time - time.time()))
    return console

def reboot(domain, console=None,
           shutdown_timeout=SHUTDOWN_TIMEOUT,
           startup_timeout=STARTUP_TIMEOUT):
    console = console or domain.console()
    if not console:
        domain.logger.error("domain is shutdown")
        return None
    domain.logger.info("rebooting domain")
    domain.reboot()
    console.expect("\[\s*[0-9]+\.[0-9]+]\s+reboot:", timeout=SHUTDOWN_TIMEOUT)
    domain.logger.info("domain reset")
    _startup(domain, console, timeout=startup_timeout)
    return console

# Use the console to detect the shutdown - if/when the domain stops it
# will exit giving an EOF.

def shutdown(domain, console=None, shutdown_timeout=SHUTDOWN_TIMEOUT):
    console = console or domain.console()
    if not console:
        domain.logger.error("domain already shutdown")
        return None
    domain.logger.info("shutting down domain")
    domain.shutdown()
    domain.logger.debug("waiting %s seconds for console to close", shutdown_timeout)
    if console.expect([pexpect.EOF,pexpect.TIMEOUT], timeout=shutdown_timeout):
        domain.logger.error("timeout waiting for shutdown, giving up")
        return True
    domain.logger.info("domain shutdown")
    return False
