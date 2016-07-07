# Utils directory, for libreswan
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
from os import path

def _directory(*util):
    return path.join(path.dirname(sys.argv[0]), *util)

def realpath(*util):
    return path.realpath(_directory(*util))

def relpath(*util):
    return path.relpath(_directory(*util))
