#!/usr/bin/python3

# Copyright (C) 2020 Paul Wouters <pwouters@redhat.com>
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


import threading
import time
import optparse
import sys
import subprocess
import os
import glob
import time
from pathlib import Path

passed = []
failed = []
nsrun = ""
verbose = False

def task(test):
    global passed
    global failed
    global verbose
    output = ""
    print("START: %s"%test)
    try:
        output = subprocess.check_output("%s --ns --shutdown --exitcode --testname %s"%(nsrun,test), stderr=subprocess.STDOUT, shell=True)
        print("   PASSED: %s"%test)
        passed.append(test)
    except:
        print("   FAILED: %s"%test)
        failed.append(test)
    if (verbose):
        print(output)

def main():
    global num
    global nsrun
    global verbose
    global diff

    start = time.time()

    nsrun = "%s/nsrun"% os.path.dirname(sys.argv[0])
    usage = "usage: namespace-runner.py [-j num] [---verbose] [--diff] testname1 testname2 ..."
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-j", action="store", dest="num", default=5,
        help="number of tests to run in parallel")
    parser.add_option("-v", "--verbose", action="store_true", default=False, dest="verbose",
        help="show verbose nsrun output - output will interleave with threads")
    parser.add_option("-d", "--diff", action="store_true", default=False, dest="diff",
        help="show diff output after all tests have run")
    (options, args) = parser.parse_args()
    if not args:
        parser.print_help()
        sys.exit(1)

    num = options.num
    verbose = options.verbose
    diff = options.diff

    print("running queue of %s"%num)
    print("testlist: %s"%" ".join(args))

    threads = list()
    for i in args:
        test = os.path.basename(i)
        thread = threading.Thread(target=task,args=(test,))
        threads.append(thread)
        thread.start()

        while threading.active_count() > int(num):
            #print("\n Active threads: %s"% str(threading.active_count()-1) )
            time.sleep(1)

    for ex in threads:
        ex.join()

    if (diff):
        testdir = "%s/../pluto/"% os.path.dirname(sys.argv[0])
        for failure in failed:
            print("\n\n\n------------- %s diff  -------------------"%failure)
            files = glob.glob("%s/%s/OUTPUT/*.diff"%(testdir,failure))
            for f in files:
                if Path(f).stat().st_size > 0:
                    with open(f, 'r') as f:
                        print(f.read())

    elapsed = time.time() - start
    timestr = time.strftime("%H:%M:%S", time.gmtime(elapsed))

    print("\n\n\n-----------------------")
    print("total  tests: %d"%(len(passed) + len(failed)))
    print("passed tests: %d"%len(passed))
    print("failed tests: %d"%len(failed))
    print("runtime: %s"%timestr)
    print("-----------------------")
    print("passed tests: %s"%" ".join(passed))
    print("-----------------------")
    print("failed tests: %s"%" ".join(failed))


    if (len(failed) != 0):
        sys.exit(1)

if __name__ == "__main__":
    main()

