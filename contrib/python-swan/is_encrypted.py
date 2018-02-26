#!/usr/bin/python2 -tt
# -*- coding: utf-8 -*-

"""Is connection encrypted?

./is_encrypted.py --debug --port 443 10.6.6.1
./is_encrypted.py --debug --source 2001:998:2e:f00::42 2a00:1190:c00a:f00::1
./is_encrypted.py --debug --source 193.65.3.113 172.27.129.42
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
