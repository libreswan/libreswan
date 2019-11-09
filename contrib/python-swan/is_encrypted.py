#!/usr/bin/python2 -tt
# -*- coding: utf-8 -*-

"""Is connection encrypted?

./is_encrypted.py --debug --port 443 10.6.6.1
./is_encrypted.py --debug --source 2001:998:2e:f00::42 2a00:1190:c00a:f00::1
./is_encrypted.py --debug --source 193.65.3.113 172.27.129.42

/*
 * Is connection encrypted? -utility.
 *
 * Copyright (C) 2018  Kim B. Heino <b@bbbs.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
"""

from __future__ import print_function
from __future__ import unicode_literals
import argparse
import swan


def main():
    """Main program"""
    parser = argparse.ArgumentParser(
        description='check if traffic would get encrypted by IPsec')
    parser.add_argument('--debug', action='store_true', help='show debugging')
    parser.add_argument('--source', help='source address of the packet')
    parser.add_argument('--port', help='connect to TCP port on destination')
    parser.add_argument('destination', help='destination IP address to check')
    args = parser.parse_args()

    print(swan.is_encrypted(
        args.destination, args.port, args.source, debug=args.debug))


if __name__ == '__main__':
    main()
