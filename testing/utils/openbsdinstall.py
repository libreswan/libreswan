#!/usr/bin/env python3

# pexpect script to Install OpenBSD base Domain
#
# Copyright (C) 2020 Ravi Teja <hello@rtcms.dev>
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
KVM_BSD_BASE_NAME = str(sys.argv[1])
def es(child,expect,send,t=30):
	try:
		child.expect(expect,timeout=t)
		child.send(send+'\n')
	except:
		print("==> Error Executing "+send+" Command <==")
		print("==> Error <==\n"+child.before+"\n ==========")

try:
    child = pexpect.spawnu(str(sys.argv[2]),encoding='utf-8')
    child.expect('boot>')
except:
    print("==> Error Conecting to the Shell <==")
    print(child.before)
    print('==> Exiting the program...!')
    sys.exit(0)
child.logfile = sys.stdout
#sleep for 10 seconds approx so that all those initial boot log loads - Optional
time.sleep(10)
#REGx for Installation prompt
#To enter Shell mode
es(child,'.*hell?','S')
#Mounting of drive where install.conf file is present
es(child,'# ','mount /dev/cd0c /mnt')
#Copying of install.conf file
es(child,'# ','cp /mnt/install.conf /')
es(child,'#','cp /mnt/rc.firsttime /')
es(child,'# ','umount /mnt')
#Installing by taking deafult params from install.conf file
es(child,'# ','install -af /install.conf')
#This is to check if all the installation files got copied(because it's slow on some systems)
while(child.expect([".*install has been successfully completed!", pexpect.EOF, pexpect.TIMEOUT],timeout=10)!=0):
        continue
#To copy rc.girsttime file in the right directory
es(child,'.*bsd-base# ','mv rc.firsttime /mnt/etc/',100)
#to enable iked
es(child,'.*bsd-base# ','echo "iked_flags=YES" >> /mnt/etc/rc.conf.local')
print('====> Shutting Down Base Domain <====')
#To shutdown the base domain
es(child,'.*bsd-base# ','halt -p\n')
print("Waiting 10 seconds to shutdown...")
time.sleep(10)
child.close()
#To force shutdown the base domain via virt manager
os.system('sudo virsh destroy '+KVM_BSD_BASE_NAME+' > /dev/null')
