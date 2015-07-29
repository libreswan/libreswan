#!/usr/bin/env python3

# Login to a vm and run a command, for libreswan
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

import sys
import argparse
import logging
import time
import os
from fab import virsh
from fab import remote
from fab import argutil
from fab import logutil

def main():

    parser = argparse.ArgumentParser(description="Connect to and run a shell command on a virtual machine domain",
                                     epilog=("If no command or file is specified an interactive shell is created."))

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
                        choices=set(["cold", "warm"]),
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

    parser.add_argument("domain", action="store",
                        help="domain (virtual machine) to connect to")
    parser.add_argument("command", nargs="?",
                        help="run shell command non-interactively")

    logutil.add_arguments(parser)
    args = parser.parse_args()
    logutil.config(args)

    # Get things started
    domain = virsh.Domain(args.domain)

    status = 0
    console = None

    # Get the current console, this will be None if the machine is
    # shutoff.
    console = domain.console()
    if args.boot:
        if args.boot == "warm":
            if console:
                remote.reboot(domain, console)
            else:
                console = remote.start(domain)
        elif args.boot == "cold":
            if console:
                remote.shutdown(domain, console)
            console = remote.start(domain)

    # Find a reason to log-in and interact with the console.
    batch = args.mode == "batch" or args.command != None
    interactive = args.mode == "interactive" or (args.command == None and args.boot == None and not args.shutdown)

    if interactive or batch:

        # If the machine hasn't been booted, do so now.
        if not console:
            console = remote.start(domain)
        remote.login(domain, console)

        if args.chdir and os.path.isabs(args.chdir):
            chdir = args.chdir
        elif args.chdir:
            chdir = remote.directory(domain, console, directory=os.path.abspath(args.chdir))
        else:
            chdir = None
        if chdir:
            domain.logger.info("'cd' to %s", chdir)
            console.chdir(chdir)

        if args.command:

            console.output(args.output)
            console.run("")

            status = console.run(args.command, timeout=args.timeout)
            print()

        if interactive:

            print()
            output = console.output(None)
            if output:
                print("info: disabled --output as it makes pexpect crash when in interactive mode.")
            if args.debug:
                print("info: pexpect ignores --debug in interactive mode!")
            print("Escape character is ^]")
            # Hack so that the prompt appears
            console.output(sys.stdout)
            console.run("")
            console.output()
            # Normal mode
            console.stty_sane()
            console.interact()

    if args.shutdown:
        shutdown_status = remote.shutdown(domain)
        status = status or shutdown_status

    sys.exit(status)

if __name__ == "__main__":
    main()
