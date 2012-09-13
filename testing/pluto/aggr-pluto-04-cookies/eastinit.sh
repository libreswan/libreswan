: ==== start ====
#ipsec setup stop
#umount /var/tmp; mount /var/tmp
#umount /usr/local; mount /usr/local

TESTNAME=aggr-pluto-04-cookies
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/aggr.record 

ipsec auto --add westnet-eastnet-aggr
echo done
