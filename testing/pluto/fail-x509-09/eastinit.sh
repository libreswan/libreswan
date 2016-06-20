TESTNAME=fail-x509-09
source /testing/pluto/bin/eastlocal.sh

rm /tmp/$TESTNAME/ipsec.d/certs/west*
rm /tmp/$TESTNAME/ipsec.d/crls/ca.crl

iptables -A INPUT -i eth1 -s 192.0.3.0/24 -d 0.0.0.0/0 -j DROP

ipsec start
/testing/pluto/basic-pluto-01/eroutewait.sh trap

ipsec auto --add westnet-eastnet-x509-cr

