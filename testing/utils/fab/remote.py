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

LOGIN = rb'root'
LOGIN_PROMPT = rb'login: $'
LOGIN_PROMPT_TIMEOUT = 120

PASSWORD = rb'swan'
PASSWORD_PROMPT = rb'Password:\s?$'
PASSWORD_PROMPT_TIMEOUT = 5

# Domain timeouts

SHUTDOWN_TIMEOUT = 20

# Assuming the machine is booted, try to log-in.

LOGIN_TIMEOUT = 10
PASSWORD_TIMEOUT = 10
SHELL_TIMEOUT = 10

def _login(domain, console, login, password,
           lapsed_time, timeout):

    tries = 0
    while True:
        if tries > 3:
            domain.logger.error("giving up after %s and %d attempts at logging in",
                                lapsed_time, tries)
            raise pexpect.TIMEOUT("too many login attempts with domain %s" % domain)

        # Hopefully "Last login" is matched before "login: "
        match = console.expect([LOGIN_PROMPT,
                                PASSWORD_PROMPT,
                                b'Last login',
                                console.prompt],
                               timeout=timeout)
        if match == 0:
            timeout = PASSWORD_TIMEOUT
            domain.logger.info("got login prompt after %s; sending '%s' and waiting %s seconds for password prompt",
                               lapsed_time, login, timeout)
            console.sendline(login)
            tries = tries + 1
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

    # Sync with the remote end by matching a known and unique pattern.
    # Strictly match PATTERN+PROMPT so that earlier prompts that might
    # also be lurking in the output are discarded.
    number = str(random.randrange(10000, 1000000))
    sync = "sync=" + number + "=cnyc"
    console.sendline("echo " + sync)
    console.expect(sync.encode() + rb'\s+' + console.prompt.pattern, timeout=virsh.TIMEOUT)

    # Set the PTY inside the VM to no-echo; kvmsh.py's interactive
    # mode will re-adjust this.
    console.run("export TERM=dumb ; unset LS_COLORS ; stty sane -echo -onlcr")

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

def boot_to_login_prompt(domain):

    console = domain.start()
    console.expect([LOGIN_PROMPT], timeout=LOGIN_PROMPT_TIMEOUT)
    domain.logger.info("domain reached Login: prompt")
    return console
