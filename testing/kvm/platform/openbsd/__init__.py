#!/usr/bin/env python3

# pexpect script to Install OpenBSD base Domain
#
# Copyright (C) 2020 Ravi Teja <hello@rtcms.dev>
# Copyright (C) 2021-2023 Andrew Cagney
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

import pexpect
import sys
import time
import os

FILTER_OUTPUT = False

def es(child, expect, send, t=60):
    try:
        print("expecting", expect);
        child.expect(expect,timeout=t)
        print("sending", send);
        child.send(send+'\n')
    except:
        print("==> Error Executing >>"+send+"<< Command <==")
        print("==> Error <==\n"+child.before+"\n ==========")
        sys.exit(1)

def install_base(child, param):

    print("waiting for boot");
    child.expect('boot>', timeout=180)

    #sleep for 10 seconds so that all those initial boot log loads
    time.sleep(10)
    #REGx for Installation prompt
    #To enter Shell mode
    es(child,'.*hell?','S')

    #Mounting of drive where install.conf file is located
    es(child,'# ','mount /dev/cd0c /mnt')
    #Copying of install.conf file
    es(child,'# ','cp /mnt/base.conf /')
    es(child,'# ','cp /mnt/base.sh /')
    es(child,'# ','cp /mnt/base.disk /')
    #Unmounting the drive
    es(child,'# ','umount /mnt')

    #Installing by taking answers from install.conf file
    es(child,'# ','install -af /base.conf')
    #This is to check if all the installation files got copied(it's slow on some systems)
    while child.expect([".*install has been successfully completed!",
                        pexpect.EOF,
                        pexpect.TIMEOUT], timeout=10) != 0:
        continue

    # customize the install
    es(child,'# ','/bin/sh -x /base.sh')

    #child.logfile = None
    #child.interact()
    #exit(0)

    #To shutdown the base domain
    es(child,'openbsd# ','sync ; sync ; sync\n')
    es(child,'openbsd# ','halt -p\n')

    print("Waiting for shutdown...")
    time.sleep(20)
    child.close()
    #To force shutdown the base domain via virt manager
    os.system('sudo virsh destroy ' + param.domain + ' > /dev/null')
