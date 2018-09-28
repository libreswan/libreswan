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

import re
import os
import logging
import pexpect
import time

from fab import virsh
from fab import shell
from fab import timing
from fab import logutil

MOUNTS = {}

def mounts(domain):
    """Return a table of 9p mounts for the given domain"""
    # maintain a local cache
    if domain in MOUNTS:
        mounts = MOUNTS[domain]
        domain.logger.debug("using mounts from cache: %s", mounts)
        return
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
    domain.logger.debug("extracted mounts: %s", mounts)
    return mounts


FSTABS = {}

def mount_point(domain, console, device):
    """Find the mount-point for device"""
    if not domain in FSTABS:
        FSTABS[domain] = {}
    fstab = FSTABS[domain]
    if device in fstab:
        mount = fstab[device]
        domain.logger.debug("using fstab entry for %s (%s) from cache", device, mount)
        return mount;
    console.sendline("awk '$1==\"" + device + "\" { print $2 }' < /etc/fstab")
    status, match = console.expect_prompt("(/\S+)")
    mount = match.group(1)
    fstab[device] = mount
    domain.logger.debug("fstab has device '%s' mounted on '%s'", device, mount)
    return mount


# Map the local PATH onto a domain DIRECTORY
def path(domain, console, path):
    path = os.path.realpath(path)
    # Because .items() returns an unordered list (it can change across
    # python invocations or even within python as the dictionary
    # evolves) it first needs to be sorted.  Use the DIRECTORY sorted
    # in reverse so that /source/testing comes before /source - and
    # the longer path is prefered.
    device_directory = sorted(mounts(domain).items(),
                              key=lambda item: item[1],
                              reverse=True)
    domain.logger.debug("ordered device/directory %s", device_directory);
    for device, directory in device_directory:
        if os.path.commonprefix([directory, path]) == directory:
            # found the local directory path that is mounted on the
            # machine, now map that onto a remote path
            root = mount_point(domain, console, device)
            return root + path[len(directory):]

    raise AssertionError("the host path '%s' is not mounted on the guest %s" % (path, domain))


# Domain timeouts

SHUTDOWN_TIMEOUT = 20
START_TIMEOUT = 10
LOGIN_PROMPT_TIMEOUT = 120

def _wait_for_login_prompt(domain, console, timeout, also_expect=[]):
    # If match is non-empty, append it, so the first index is 1
    timer = timing.Lapsed()
    # Create a new list, otherwise the default [] ends up containing
    # lots of login prompts ...
    matches = ["login: "] + also_expect
    domain.logger.debug("waiting %d seconds for %s",
                        timeout, " or ".join(ascii(match) for match in matches))
    match = console.expect(matches, timeout=timeout)
    # always report a prompt match, let caller decide if other cases
    # should be verbose.
    domain.logger.log(match == 0 and logutil.INFO or logutil.DEBUG,
                      "%s matched after %s", ascii(matches[match]), timer)
    return match


# Assuming the machine is booted, try to log-in.

LOGIN_TIMEOUT = 10
PASSWORD_TIMEOUT = 5
SHELL_TIMEOUT = 5

def _login(domain, console, username, password, login_timeout, password_timeout, shell_timeout):

    lapsed_time = timing.Lapsed()

    domain.logger.info("waiting %s seconds for login prompt; %s seconds for password prompt; %s seconds for shell prompt",
                       login_timeout, password_timeout, shell_timeout)
    domain.logger.debug("console prompt: %s", console.prompt.pattern)

    domain.logger.debug("sending control-c+carriage return, waiting %s seconds for login or shell prompt", login_timeout)
    console.sendintr()
    console.sendline("")
    if _wait_for_login_prompt(domain, console, timeout=login_timeout,
                              also_expect=[console.prompt]) == 1:
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


# Get a domain running with an attatched console.  Should be really
# quick.

def _start(domain, timeout):
    domain.logger.info("starting domain")
    # Bring the machine up from scratch.
    end_time = time.time() + timeout
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

def _reboot_to_login_prompt(domain, console):

    # Drain any existing output.
    console.drain()

    # The reboot pattern needs to match all the output up to the point
    # where the machine is reset.  That way, the next pattern below
    # can detect that the reset did something and the machine is
    # probably rebooting.
    timeouts = [SHUTDOWN_TIMEOUT, START_TIMEOUT, LOGIN_PROMPT_TIMEOUT]
    timeout = 0
    for t in timeouts:
        timeout += t
    domain.logger.info("waiting %s seconds for reboot and login prompt", timeout)
    domain.reboot()
    timer = timing.Lapsed()
    for timeout in timeouts:
        # pexpect's pattern matcher is buggy and, if there is too much
        # output, it may not match "reboot".  virsh's behaviour is
        # also buggy, see further down.
        match = _wait_for_login_prompt(domain, console, timeout=timeout,
                                       also_expect=["reboot: Power down\r\n",
                                                    pexpect.EOF,
                                                    pexpect.TIMEOUT])
        if match == 0:
            return console
        elif match == 1:
            domain.logger.info("domain rebooted after %s", timer)
        elif match == 2:
            # On F26, in response to the reset(?), virsh will
            # spontaneously disconnect.
            domain.logger.error("domain disconnected spontaneously after %s", timer)
            break
        elif match == 3 and console.child.buffer == "":
            # On F23, F24, F25, instead of resetting, the domain will
            # hang.  The symptoms are a .TIMEOUT and an empty buffer
            # (HACK!).
            domain.logger.error("domain appears stuck, no output received after waiting %d seconds",
                                timeout)
            break

    # Things aren't going well.  Per above Fedora can screw up or the
    # domain is just really slow.  Try destroying the domain and then
    # cold booting it.

    destroy = True
    if domain.state() == virsh.STATE.PAUSED:
        destroy = False
        domain.logger.error("domain suspended, trying resume")
        status, output = domain.resume()
        if status:
            domain.logger.error("domain resume failed: %s", output)
            destroy = True
    if destroy:
        domain.logger.error("domain hung, trying to pull the power cord")
        domain.destroy()
        console.expect_exact(pexpect.EOF, timeout=SHUTDOWN_TIMEOUT)
        console = _start(domain, timeout=START_TIMEOUT)

    # Now wait for login prompt.  If this second attempt fails then
    # either a .TIMEOUT or a .EOF exception will be thrown and the
    # test will be aborted (marked as unresolved).
    _wait_for_login_prompt(domain, console, timeout=LOGIN_PROMPT_TIMEOUT)
    return console


def boot_to_login_prompt(domain, console):

    if console:
        return _reboot_to_login_prompt(domain, console)
    else:
        console = _start(domain, timeout=START_TIMEOUT)
        _wait_for_login_prompt(domain, console, timeout=LOGIN_PROMPT_TIMEOUT)
        return console
