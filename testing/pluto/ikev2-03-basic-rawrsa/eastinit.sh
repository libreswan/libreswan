: ==== start ====
TESTNAME=ikev2-03-basic-rawrsa
/testing/pluto/bin/wait-until-network-ready

source /testing/pluto/bin/eastlocal.sh

ipsec setup stop
rm -f /tmp/pluto.log
ln -s /testing/pluto/$TESTNAME/OUTPUT/pluto.east.log /tmp/pluto.log

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add  westnet-eastnet-ikev2
ipsec whack --debug-control --debug-controlmore --debug-crypt
echo "initdone"
