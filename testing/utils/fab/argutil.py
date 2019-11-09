# Some argument parsing functions.
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

import sys
import os

from fab import tee

class MetaList(type):
    def __new__(cls, name, bases, namespace, **kwds):
        result = type.__new__(cls, name, bases, namespace, **kwds)

        # The string names are mapped onto the canonical member names
        # so that that the construct:
        #
        #    for p in List(List.member): p is List.member"
        #
        # works.
        members = {}
        for name, value in namespace.items():
            # good enough for now
            if name.startswith("__"):
                continue
            members[value] = value
        result._members_ = members
        result._metavar_ = "{" + ",".join(sorted(members)) + "},..."
        return result
    def __str__(cls):
        return cls._metavar_

class List(metaclass=MetaList):
    def __init__(self, *args):
        self.args = []
        for arg in args:
            for member in arg.split(","):
                if not member:
                    # ignore ''
                    continue
                if member in self._members_:
                    # Form the list using the member values, not some
                    # equivalent string.  Ignore ''.
                    self.args.append(self._members_[member])
                else:
                    raise ValueError()
    def __iter__(self):
        return self.args.__iter__()
    def __str__(self):
        return ",".join(self.args)
    def __contains__(self, member):
        return member in self.args
    def __bool__(self):
        return bool(self.args)


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

def directory(arg):
    if os.path.isdir(arg):
        return arg
    raise Exception("directory '%s' not found" % arg)

def directory_file(arg):
    d,b = os.path.split(arg)
    if os.path.isdir(d):
        return arg
    raise Exception("directory '%d' for file '%s' not found" % (d, b))

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
