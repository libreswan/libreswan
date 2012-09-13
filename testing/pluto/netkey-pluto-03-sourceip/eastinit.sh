: ==== start ====
TESTNAME=netkey-pluto-03-sourceip
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-east-sourceip
