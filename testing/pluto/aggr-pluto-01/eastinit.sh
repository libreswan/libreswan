: ==== start ====
#ipsec setup stop
#umount /var/tmp; mount /var/tmp
#umount /usr/local; mount /usr/local

TESTNAME=aggr-pluto-01
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/basic-pluto-01/eroutewait.sh trap
ipsec auto --add westnet-eastnet-aggr
echo done
