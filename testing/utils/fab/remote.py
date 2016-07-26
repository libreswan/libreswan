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

import re
import os
import logging
import pexpect
import time
from fab import virsh
from fab import shell
from fab import timing


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
            # Strip trailing "/" along with other potential quirks
            # such as the mount point being a soft link.
            source = os.path.realpath(source)
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
    directory = os.path.realpath(directory)
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

STARTUP_TIMEOUT = 60
SHUTDOWN_TIMEOUT = 20

def _startup(domain, console, timeout=STARTUP_TIMEOUT):
    expected = "Started Login Service"
    # XXX: While searchwindowsize=len(expected) should technically be
    # sufficient to speed up matching, it isn't.  In fact, when more
    # than searchwindowsize is read as a single block, pexpect only
    # searchs the last searchwindowsize characters missing anything
    # before it.
    #
    # See: https://github.com/pexpect/pexpect/issues/203
    domain.logger.info("waiting %d seconds for domain to start (%s)", timeout, expected)
    lapsed_time = timing.Lapsed()
    console.expect_exact(expected, timeout=timeout)
    domain.logger.info("domain started after %s", lapsed_time)


# Assuming the machine is booted, try to log-in.

def _login(domain, console, username, password,
           login_timeout, password_timeout, shell_timeout):

    lapsed_time = timing.Lapsed()

    domain.logger.info("waiting %s seconds for login prompt; %s seconds for password prompt; %s seconds for shell prompt",
                       login_timeout, password_timeout, shell_timeout)
    domain.logger.debug("console prompt: %s", console.prompt.pattern)

    domain.logger.debug("sending control-c+carriage return, waiting %s seconds for login or shell prompt", login_timeout)
    console.sendintr()
    console.sendline("")
    if console.expect(["login: ", console.prompt], timeout=login_timeout):
        # shell prompt
        domain.logger.info("We're in after %s!  Someone forgot to log out ...", lapsed_time)
        return

    domain.logger.debug("sending username '%s' waiting %s seconds for password or shell prompt", \
                        username, password_timeout)
    console.sendline(username)
    if console.expect(["Password: ", console.prompt], timeout=password_timeout):
        # shell prompt
        domain.logger.info("We're in after %s! No password ...", lapsed_time)
        return

    domain.logger.debug("sending password '%s', waiting %s seconds for shell prompt",
                        password, shell_timeout)
    console.sendline(password)
    console.expect(console.prompt, timeout=shell_timeout)
    domain.logger.info("We're in after %s!", lapsed_time)


LOGIN_TIMEOUT = 120
PASSWORD_TIMEOUT = 5
SHELL_TIMEOUT = 5

# The machine is assumed to be booted.

def login(domain, console,
          username="root", password="swan",
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


def _start(domain, startup_timeout=STARTUP_TIMEOUT):
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
    return console


def start(domain, startup_timeout=STARTUP_TIMEOUT):
    console = _start(domain, startup_timeout)
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
    domain.logger.info("waiting %d seconds for domain to reboot", shutdown_timeout)
    lapsed_time = timing.Lapsed()
    domain.reboot()

    try:
        console.expect("\[\s*[0-9]+\.[0-9]+]\s+reboot:", timeout=SHUTDOWN_TIMEOUT)
        domain.logger.info("domain rebooted after %s", lapsed_time)
    except pexpect.TIMEOUT:
        domain.logger.error("domain failed to reboot after %s, resetting it", lapsed_time)
        domain.reset()
        # give the domain extra time to start
        startup_timeout = startup_timeout * 4

    try:
        _startup(domain, console, timeout=startup_timeout)
        return console
    except pexpect.TIMEOUT:
        domain.logger.error("domain failed to start after %s, power cycling it", lapsed_time)
        # On F23 the domain sometimes becomes wedged in the PAUSED
        # state.  When it does, give it a full reset.
        if domain.state() == virsh.STATE.PAUSED:
            domain.destroy()
        else:
            domain.shutdown()
        console.expect(pexpect.EOF, timeout=shutdown_timeout)
        return start(domain)


# Use the console to detect the shutdown - if/when the domain stops it
# will exit giving an EOF.

def shutdown(domain, console=None, shutdown_timeout=SHUTDOWN_TIMEOUT):
    lapsed_time = timing.Lapsed()
    console = console or domain.console()
    if not console:
        domain.logger.error("domain already shutdown")
        return None
    domain.logger.info("waiting %d seconds for domain to shutdown", shutdown_timeout)
    domain.shutdown()
    if console.expect([pexpect.EOF,pexpect.TIMEOUT], timeout=shutdown_timeout):
        domain.logger.error("timeout waiting for shutdown, destroying it")
        domain.destroy()
        if console.expect([pexpect.EOF,pexpect.TIMEOUT], timeout=shutdown_timeout):
            domain.logger.error("timeout waiting for destroy, giving up")
            return True
        return False
    domain.logger.info("domain shutdown after %s", lapsed_time)
    return False


def boot_to_login_prompt(domain, console, timeout=(STARTUP_TIMEOUT+LOGIN_TIMEOUT)):

    for attempt in range(2):

        if console:
            domain.reboot()
        else:
            console = _start(domain)

        lapsed_time = timing.Lapsed()
        domain.logger.info("waiting %s seconds for login prompt", timeout)

        if console.expect_exact([pexpect.TIMEOUT, "login: "], timeout=timeout):
            domain.logger.info("login prompt appeared after %s", lapsed_time)
            return console

        domain.logger.error("domain failed to start after %s, power cycling it", lapsed_time)
        # On F23 the domain sometimes becomes wedged in the PAUSED
        # state.  When it does, give it a full reset.
        if domain.state() == virsh.STATE.PAUSED:
            domain.destroy()
        else:
            domain.shutdown()
            console.expect(pexpect.EOF, timeout=SHUTDOWN_TIMEOUT)
        console = None

    raise pexpect.TIMEOUT("Domain %s did not reach login prompt" % domain)
