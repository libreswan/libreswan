TESTNAME=fail-x509-08
source /testing/pluto/bin/westlocal.sh

# confirm that the network is alive
../../pluto/bin/wait-until-alive 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
# confirm with a ping
ping -n -c 4 192.0.2.254

ipsec start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/basic-pluto-01/eroutewait.sh trap

ipsec auto --add westnet-eastnet-x509-cr

ipsec whack --debug-control --debug-emitting
ipsec auto --up  westnet-eastnet-x509-cr

echo done

