# Stuff to talk to virsh, for libreswan
#
# Copyright (C) 2015-2019  Andrew Cagney
# Copyright (C) 2020  Ravi Teja
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

LOGIN = rb'root'
LOGIN_PROMPT = rb'login: $'
LOGIN_PROMPT_TIMEOUT = 120

PASSWORD = rb'swan'
PASSWORD_PROMPT = rb'Password:\s?$'
PASSWORD_PROMPT_TIMEOUT = 5

# Domain timeouts

SHUTDOWN_TIMEOUT = 20
START_TIMEOUT = 20

# Assuming the machine is booted, try to log-in.

LOGIN_TIMEOUT = 10
PASSWORD_TIMEOUT = 5
SHELL_TIMEOUT = 5

def _login(domain, console, login, password,
           lapsed_time, timeout):

    tries = 0
    while True:
        if tries > 3:
            domain.logger.error("giving up after %s and %d attempts at logging in",
                                lapsed_time, tries)
            raise pexpect.TIMEOUT()
        tries = tries + 1

        # Hopefully "Last login" is matched before "login: "
        match = console.expect([LOGIN_PROMPT, PASSWORD_PROMPT, "Last login", console.prompt],
                               timeout=timeout)
        if match == 0:
            timeout = PASSWORD_TIMEOUT
            domain.logger.info("got login prompt after %s; sending '%s' and waiting %s seconds for password prompt",
                               lapsed_time, login, timeout)
            console.sendline(login)
        elif match == 1:
            timeout = SHELL_TIMEOUT
            domain.logger.info("got password prompt after %s; sending '%s' and waiting %s seconds for shell prompt",
                               lapsed_time, password, timeout)
            console.sendline(password)
        elif match == 2:
            # Last login: looks a lot like login: ulgh!  Skip.
            domain.logger.info("got 'Last login' after %s; ignoring", lapsed_time)
        elif match == 3:
            # shell prompt
            domain.logger.info("we're in after %s!", lapsed_time)
            break

    console.sync()
    return console


# The machine is assumed to be booted; but its state is unknown.

def login(domain, console, login=LOGIN, password=PASSWORD):
    if not console:
        domain.logger.error("domain not running")
        return None

    lapsed_time = timing.Lapsed()
    timeout=LOGIN_TIMEOUT
    domain.logger.info("sending control-c+carriage return, waiting %s seconds for login (or shell) prompt",
                       timeout)
    console.sendintr()
    console.sendline("")

    # try to login
    return _login(domain, console, login=login, password=password,
                  lapsed_time=lapsed_time, timeout=timeout)


# Get a domain running with an attatched console.  Should be really
# quick.

def _start(domain, timeout):
    domain.logger.info("starting domain")
    # Do not call this when the console is functional!
    console = domain.console()
    if console:
        raise pexpect.EOF("console for domain %s already open" % domain)
    # Bring the machine up from scratch.
    end_time = time.time() + timeout
    first_attempt = True
    while console == None:
        if time.time() > end_time:
            raise pexpect.EOF("trying to start domain %s" % domain)
        status, output = domain.start()
        if status and first_attempt:
            # The first attempt at starting the domain _must_ succeed.
            # Failing is a sign that the domain was running.  Further
            # attempts might fail as things get racey.
            raise pexpect.EOF("failed to start domain %s" % output)
        # give the VM time to start and then try opening the console.
        time.sleep(1)
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
    if console.expect([pexpect.EOF, pexpect.TIMEOUT],
                      timeout=shutdown_timeout):
        domain.logger.error("timeout waiting for shutdown, destroying it")
        domain.destroy()
        if console.expect([pexpect.EOF, pexpect.TIMEOUT],
                          timeout=shutdown_timeout):
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
        match = console.expect([LOGIN_PROMPT,
                                "reboot: Power down\r\n",
                                pexpect.EOF,
                                pexpect.TIMEOUT],
                               timeout=timeout)
        if match == 0:
            # login prompt (reboot message was missed)
            return console
        elif match == 1:
            # reboot message
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
    console.expect([LOGIN_PROMPT], timeout=LOGIN_PROMPT_TIMEOUT)
    return console


def boot_to_login_prompt(domain, console):

    if console:
        return _reboot_to_login_prompt(domain, console)
    else:
        console = _start(domain, timeout=START_TIMEOUT)
        console.expect([LOGIN_PROMPT], timeout=LOGIN_PROMPT_TIMEOUT)
        return console


def boot_and_login(domain, console, login=LOGIN, password=PASSWORD):

    console = boot_to_login_prompt(domain, console)
    if not console:
        domain.logger.error("domain not running")
        return None
    # try to login
    timeout = PASSWORD_TIMEOUT
    domain.logger.info("got login prompt; sending '%s' and waiting %s seconds for password (or shell) prompt", \
                       login, timeout)
    console.sendline(login)
    return _login(domain, console, login=login, password=password,
                  lapsed_time=timing.Lapsed(), timeout=timeout)
