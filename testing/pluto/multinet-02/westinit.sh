: ==== start ====
# confirm that the network is alive
# note if umlswanroot uses debian ping, "ping -s might not work properly"
ping -n -c 4 -s 192.0.1.1 192.0.2.30
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.0.0/16 -j DROP
# confirm with pings between all subnets
# west/left picks first ip in range
# east/right picks last ip in range

TESTNAME=multinet-02
source /testing/pluto/bin/westlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-subnets
