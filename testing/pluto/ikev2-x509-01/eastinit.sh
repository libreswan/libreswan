: ==== start ====
TESTNAME=ikev2-x509-01
source /testing/pluto/bin/eastnlocal.sh

iptables -A INPUT -i eth1 -s 192.0.3.0/24 -d 0.0.0.0/0 -j DROP

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "done"
