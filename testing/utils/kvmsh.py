#!/usr/bin/env python3

# Login to a vm and run a command, for libreswan
#
# Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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

import signal
import faulthandler
import sys
import argparse
import logging
import time
import os
from enum import Enum

from fab import virsh
from fab import remote
from fab import argutil
from fab import logutil
from fab import pathutil
from fab import hosts

class Boot(Enum):
    cold = "cold"
    warm = "warm"


def main():

    # If SIGUSR1, backtrace all threads; hopefully this is early
    # enough.
    faulthandler.register(signal.SIGUSR1)

    parser = argparse.ArgumentParser(description="Connect to and run a shell command on a virtual machine domain",
                                     epilog="If no command or file is specified an interactive shell is created.  SIGUSR1 will dump all thread stacks")

    parser.add_argument("--timeout", type=argutil.timeout, default=None,
                        help=("maximum runtime for the command"
                              "; -1 for no timeout"
                              " (default: no timeout)"))
    argutil.add_redirect_argument(parser, "re-direct console output from stdout to %(metavar)s",
                                  "--output", "-o",
                                  default=sys.stdout, metavar="FILE")

    parser.add_argument("--chdir", default=None, action="store", metavar="PATH",
                        help=("first change directory to %(metavar)s on the remote"
                              " domain and update prompt-match logic to expect"
                              " that directory"
                              "; an absolute %(metavar)s is used unmodified"
                              "; a relative  %(metavar)s, which is interpreted"
                              " as relative to the current local working directory"
                              ", is converted to an absolute remote path before use"
                              " (default: leave directory unchanged)"))
    parser.add_argument("--boot", default=None, action="store",
                        type=Boot, choices=[e for e in Boot],
                        help=("force the domain to boot"
                              "; 'cold': power-off any existing domain"
                              "; 'warm': reboot any existing domain"
                              " (default: leave existing domain running)"))
    parser.add_argument("--shutdown", default=False, action="store_true",
                        help=("on-completion shut down the domain"
                              " (default: leave the domain running)"))
    parser.add_argument("--mode", default=None,
                        choices=set(["interactive", "batch"]),
                        help=("enter mode"
                              " (default: if there is no command enter interactive mode)"))
    parser.add_argument("--guest-name", default=None,
                        help="The virtual machine guest's name")

    parser.add_argument("domain_name", action="store", metavar="DOMAIN",
                        help="virtual machine (domain) to connect to")

    parser.add_argument("command", nargs=argparse.REMAINDER, metavar="COMMAND",
                        help="run shell command non-interactively; WARNING#1: this simply concatenates remaining arguments with spaces; WARNING#2: this does not try to escape arguments before passing them onto the domain's shell")

    logutil.add_arguments(parser)

    # These three calls go together
    args = parser.parse_args()
    logutil.config(args, sys.stderr)
    logger = logutil.getLogger("kvmsh", args.domain_name)

    # Get things started
    domain = virsh.Domain(logger, name=args.domain_name,
                          guest=hosts.lookup(args.guest_name))

    # Find a reason to log-in and interact with the console.
    batch = args.mode == "batch" or args.command
    interactive = args.mode == "interactive" or (not args.command and args.boot == None and not args.shutdown)

    # Get the current console, this will be None if the machine is
    # shutoff (and forced to none if a cold boot)

    if args.boot is Boot.cold and domain.console():
        domain.shutdown()

    status = 0
    if args.boot and not (interactive or batch):

        console = remote.boot_to_login_prompt(domain)

    elif interactive or batch:

        console = domain.console()
        if not console:
            console = remote.boot_to_login_prompt(domain)
        if not console:
            logger.error("no domain")
            sys.exit(1)

        remote.login(domain, console)

        if args.chdir and os.path.isabs(args.chdir):
            chdir = args.chdir
        elif args.chdir:
            # convert host path to guest path
            chdir = pathutil.guest_path(domain, args.chdir)
        else:
            chdir = None
        if chdir:
            domain.logger.info("'cd' to %s", chdir)
            console.chdir(chdir)

        if args.command:

            if interactive:
                logger.info("info: option --output disabled as it makes pexpect crash when in interactive mode.")
            else:
                console.redirect_output(args.output)
            console.run("")

            status = console.run(' '.join(args.command), timeout=args.timeout)
            print()

        if interactive:

            print()
            if args.debug:
                logger.info("info: pexpect ignores --debug in interactive mode!")
            logger.info("Escape character is ^]")
            # Hack so that the prompt appears
            console.redirect_output(sys.stdout)
            console.run("")
            console.redirect_output(None)
            # Pass this terminals properties to the VM.
            columns, rows = os.get_terminal_size()
            console.run("unset LS_COLORS; export TERM=%s; stty sane rows %s columns %s"
                        % (os.getenv("TERM"), rows, columns))
            # F.A.B.
            console.interact()

    if args.shutdown:
        shutdown_status = not domain.shutdown()
        status = status or shutdown_status

    sys.exit(status)

if __name__ == "__main__":
    main()
