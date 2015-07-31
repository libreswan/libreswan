# Some argument parsing functions.
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
from fab import tee

def boolean(arg):
    a = arg.lower()
    for t in [ "1", "yes", "true", "enable" ]:
        if t.startswith(a):
            return True
    for f in [ "0", "no", "false", "disable" ]:
        if f.startswith(a):
            return False
    raise Exception("Unrecognized boolean argument '%s'" % arg)

def timeout(arg):
    arg = arg.lower()
    if arg == "none" or arg == "infinite":
        return None
    v = float(arg)
    if v < 0:
        return None
    else:
        return v

def add_redirect_argument(parser, what, *args, **kwargs):
    # Can't use '-FILE' as the argument as the parser doesn't like it.
    # The prefix syntax is hacky.
    parser.add_argument(*args, type=stdout_or_open_file,
                        help=(what +
                              "; '-' is an alias for /dev/stdout"
                              "; '+%(metavar)s': append to %(metavar)s"
                              "; '=%(metavar)s': overwrite %(metavar)s (default behaviour)"
                              "; '++%(metavar)s': copy to stdout, append to %(metavar)s"
                              "; '+=%(metavar)s': copy to stdout, overwrite %(metavar)s"),
                        **kwargs)

def stdout_or_open_file(arg):
    if arg == "-":
        return sys.stdout
    elif arg.startswith("++"):
        return tee.open(sys.stdout, files=[open(arg[2:], "a")])
    elif arg.startswith("+="):
        return tee.open(sys.stdout, files=[open(arg[2:], "w")])
    elif arg.startswith("+"):
        return open(arg[1:], "a")
    elif arg.startswith("="):
        return open(arg[1:], "w")
    else:
        return open(arg, "w")
