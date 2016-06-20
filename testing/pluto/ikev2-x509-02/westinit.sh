: ==== start ====
TESTNAME=ikev2-x509-02
source /testing/pluto/bin/westlocal.sh

rm -f /tmp/$TESTNAME/ipsec.d/certs/west*
rm -f /tmp/$TESTNAME/ipsec.d/crls/nic.crl

# confirm that the network is alive
 ping -n -c 4 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
# confirm with a ping
ping -n -c 4 192.0.2.254

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add ikev2-westnet-eastnet-x509-cr
ipsec auto --status
S=5
echo "sleep ${S} sec"
sleep ${S}
echo "initdone"
