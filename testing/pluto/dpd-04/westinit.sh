: ==== start ====
TESTNAME=dpd-04
source /testing/pluto/bin/westlocal.sh

iptables -F INPUT

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started


ipsec auto --add west-east
ipsec auto --add west-eastnet
ipsec auto --add westnet-east

/testing/pluto/bin/wait-until-policy-loaded

