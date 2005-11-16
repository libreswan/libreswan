#!/bin/sh

ipsec setup stop
umount /var/tmp; mount /var/tmp
umount /usr/local; mount /usr/local

export TESTNAME=xauth-pluto-08
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add modecfg-road--eastnet-psk
/testing/pluto/bin/wait-until-pluto-started

echo done.




