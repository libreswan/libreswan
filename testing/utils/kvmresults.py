#!/usr/bin/env python3

# Print a test result summary gathered by scanning the OUTPUT.
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

import argparse
from fab import testsuite
from fab import logutil

def main():
    parser = argparse.ArgumentParser(description="results")

    testsuite.add_arguments(parser)
    logutil.add_arguments(parser)
    args = parser.parse_args()
    logutil.config(args)

    logger = logutil.getLogger("kvmresults")

    for test in testsuite.Testsuite(directory=args.testsuite_directory):
        skip = testsuite.skip(test, args)
        if skip:
            logger.debug("skipping test %s: %s", test.name, skip)
            continue
        result = test.result()
        if result:
            print("%s: passed" % (test.name))
        else:
            print("%s: %s" % (test.name, result))

if __name__ == "__main__":
    main()
