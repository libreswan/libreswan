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

import logging

def getLogger(name, *suffixes):
    """Return the logger identified by NAME and SUFFIXES

    To, hopefully, make the logger's name more friendly, any module
    prefixes are stripped, and qualifying suffixes are appended.  For
    instance, "fab.shell,east" becomes "shell east" in log messages.

    XXX: An alternative construct might be: "fab.shell,east" becomes
    "fab.shell.east"; but "shell,east" becomes "shell east".

    """

    # name == __name__ == a.b.c == [0]="a.b" [1]="." [2]="c"
    name = name.rpartition(".")[2]
    for suffix in suffixes:
        if suffix:
            name += " " + suffix
    return logging.getLogger(name)
