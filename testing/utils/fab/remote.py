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
import random
import logging
import pexpect
import time

from fab import virsh
from fab import timing
from fab import logutil

BOOT_TIMEOUT = 120 # allow time to boot

LOGIN = rb'root'
LOGIN_PROMPT = rb'login: $'
LOGIN_TIMEOUT = 10

# sent login, expecting password

PASSWORD = rb'swan'
PASSWORD_PROMPT = rb'Password:\s?$'
PASSWORD_TIMEOUT = 10

# sent password, expecting shell

SHELL_TIMEOUT = 10

# expecting some sort of output
#
# - just sent username; expecting password
# - just sent enter; expecting anything

def _login(console, logger, login, password, lapsed_time, timeout):

    tries = 1

    while True:
        if tries > 2:
            logger.error("giving up after %s and %d attempts at logging in",
                         lapsed_time, tries)
            return None

        # Hopefully "Last login" is matched before "login: "
        try:
            match console.expect([LOGIN_PROMPT,
                                  PASSWORD_PROMPT,
                                  b'Last login',
                                  console.prompt],
                                 timeout=timeout):
                case 0: # Login: prompt
                    timeout = PASSWORD_TIMEOUT
                    logger.info("got %s prompt after %s; sending '%s' and waiting %s seconds for password prompt",
                                LOGIN_PROMPT, lapsed_time, login, timeout)
                    console.sendline(login)
                    tries = tries + 1
                case 1: # Password: prompt
                    timeout = SHELL_TIMEOUT
                    logger.info("got %s prompt after %s; sending '%s' and waiting %s seconds for shell prompt",
                                PASSWORD_PROMPT, lapsed_time, password, timeout)
                    console.sendline(password)
                case 2: # Last login: looks a lot like login: ulgh!  Skip.
                    logger.info("got 'Last login' after %s; ignoring", lapsed_time)
                case 3: # Shell prompt
                    logger.info("we're in (after %s)!", lapsed_time)
                    break # out of loop
        except pexpect.TIMEOUT:
            logger.error("TIMEOUT while trying to login")
            return None
        except pexpect.EOF:
            logger.error("EOF while trying to login")
            return None

    # Sync with the remote end by matching a known and unique pattern.
    # Strictly match PATTERN+PROMPT so that earlier prompts that might
    # also be lurking in the output are discarded.
    try:
        number = str(random.randrange(10000, 1000000))
        sync = "sync=" + number + "=cnyc"
        console.sendline("echo " + sync)
        console.expect(sync.encode() + rb'\s+' + console.prompt.pattern, timeout=virsh.TIMEOUT)
    except (pexpect.TIMEOUT, pexpect.EOF) as e:
        logger.error("EXCEPTION while syncing output: %s", e)
        return None

    # Set the PTY inside the VM to no-echo; kvmsh.py's interactive
    # mode will re-adjust this.
    #
    # This can barf with a timeout when the prompt is wrong.
    try:
        console.run("export TERM=dumb ; unset LS_COLORS ; stty sane -echo -onlcr")
    except (pexpect.TIMEOUT, pexpect.EOF) as e:
        logger.error("EXCEPTION while setting terminal mode: %s", e)
        return None

    return console

# The machine is assumed to be booted; but its state is unknown.

def login(domain, console, login=LOGIN, password=PASSWORD):

    logger = domain.logger
    if not console:
        domain.logger.error("domain not running")
        return None

    lapsed_time = timing.Lapsed()

    logger.info("hitting enter (control-c+carriage return)")
    console.sendintr()
    console.sendline("")

    # try to login
    if not _login(console, logger, login=login, password=password,
                  lapsed_time=lapsed_time, timeout=LOGIN_TIMEOUT):
        return None

    return console


def boot_to_login_prompt(domain):

    console = domain.start()
    try:
        match console.expect([LOGIN_PROMPT],
                             timeout=BOOT_TIMEOUT):
            case 0:
                domain.logger.info("domain reached Login: prompt")
                return console
    except pexpect.TIMEOUT:
        domain.logger.error("TIMEOUT waiting for Login: prompt")
        return None


def boot_and_login(domain):
    logger = domain.logger
    lapsed_time = timing.Lapsed()

    tries = 1
    while True:

        console = domain.start()
        if not console:
            logger.error("domain did not start (boot attempt %d and %s); giving up",
                         tries, lapsed_time)
            return None

        # wait for just the login prompt
        problem = None
        try:
            match console.expect([LOGIN_PROMPT], timeout=BOOT_TIMEOUT):
                case 0:
                    logger.info("boot successful (boot attempt %d and %s)",
                                tries, lapsed_time)
                    break # out of loop
        except pexpect.TIMEOUT:
            problem = "TIMEOUT"
        except pexpect.EOF:
            problem = "EOF"

        domain.destroy()
        if tries > 2:
            logger.error("%s waiting for Login: prompt (boot attempt %d and %s); giving up",
                         problem, tries, lapsed_time)
            return None
        logger.error("%s waiting for Login: prompt (boot attempt %d and %s); retrying",
                     problem, tries, lapsed_time)
        tries = tries + 1

    # start the login and then let _login() take over
    console.sendline(LOGIN)
    if not _login(console, logger, login=LOGIN, password=PASSWORD,
                  lapsed_time=lapsed_time, timeout=PASSWORD_TIMEOUT):
        return None

    return console
