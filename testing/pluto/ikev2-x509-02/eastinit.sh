: ==== start ====
TESTNAME=ikev2-x509-02
source /testing/pluto/bin/eastlocal.sh

rm -f /tmp/$TESTNAME/ipsec.d/certs/west*
rm -f /tmp/$TESTNAME/ipsec.d/crls/nic.crl

iptables -A INPUT -i eth1 -s 192.0.3.0/24 -d 0.0.0.0/0 -j DROP

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add ikev2-westnet-eastnet-x509-cr

S=5
echo "sleep ${S} sec"
sleep ${S}
echo "initdone"
