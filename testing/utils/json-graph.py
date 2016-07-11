#!/usr/bin/env python3

# Print "graph.json" on standard output.
#
# Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

import argparse
import sys

from fab import jsonutil

def main():

    parser = argparse.ArgumentParser(description="write graph.json to standard output")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("results", metavar="table.json", nargs="+",
                        help="%(metavar)s files containing results from test runs")

    args = parser.parse_args()

    rows = []
    for result in args.results:
        args.verbose and sys.stderr.write("%s\n" % result)
        with open(result) as f:
            j = jsonutil.load(f)
            if not j:
                sys.stderr.write("%s: invalid json\n" % (result))
                continue
            if not jsonutil.table.summary in j:
                sys.stderr.write("%s: missing summary\n" % (result))
                continue
            summary = j[jsonutil.table.summary]
            rows.append(summary)

    jsonutil.dump(rows, sys.stdout)
    sys.stdout.write("\n")
    return 0

if __name__ == "__main__":
    sys.exit(main())
