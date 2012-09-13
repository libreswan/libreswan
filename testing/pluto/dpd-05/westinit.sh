: ==== start ====
TESTNAME=dpd-05
source /testing/pluto/bin/westlocal.sh

iptables -F INPUT 
iptables -F OUTPUT

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add west-east

