: ==== start ====
TESTNAME=sourceip-01
source /testing/pluto/bin/westlocal.sh

iptables -I INPUT -s 0.0.0.0/0 -d 192.0.1.0/24 -i eth1 -j REJECT
iptables -I FORWARD -s 0.0.0.0/0 -d 192.0.1.0/24 -i eth1 -j REJECT

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet--eastnet-sourceip


