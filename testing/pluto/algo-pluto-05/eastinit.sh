: ==== start ====
TESTNAME=algo-pluto-05
source /testing/pluto/bin/eastlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-both
echo done
