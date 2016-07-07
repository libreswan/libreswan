#!/usr/bin/env python3

# Print summary "table.json" on standard output.
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
from os import path

from fab import jsonutil
from fab import utilsdir

def main():

    parser = argparse.ArgumentParser(description="write summary 'table.json' to standard output")
    parser.add_argument("--rundir", action="store",
                        default=path.basename(utilsdir.realpath("..", "..")),
                        help="value to assign to runDir")
    parser.add_argument("tables", metavar="table.json", nargs="+",
                        help="%(metavar)s containing result json files")

    args = parser.parse_args()

    columns = [
        "Dir", "Passed", "Failed", "Tests", "Run Time(Hours)",
    ]

    rows = []

    for table in args.tables:
        with open(table) as f:
            j = jsonutil.load(f)
            summary = j[jsonutil.table.summary]
            row = [
                path.basename(j[jsonutil.table.rundir]),
                summary[jsonutil.summary.passed],
                summary[jsonutil.summary.failed],
                summary[jsonutil.summary.total],
                summary[jsonutil.summary.runtime],
            ]
        rows.append(row)

    table = {
        jsonutil.table.rundir: args.rundir,
        jsonutil.table.suffix: "",
        jsonutil.table.columns: columns,
        jsonutil.table.rows: rows,
    }

    jsonutil.dump(table, sys.stdout)
    sys.stdout.write("\n")
    return 0

if __name__ == "__main__":
    sys.exit(main())
