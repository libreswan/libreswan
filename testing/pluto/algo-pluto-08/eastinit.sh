: ==== start ====
TESTNAME=algo-pluto-08
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/basic-pluto-01/eroutewait.sh trap

ipsec auto --add westnet-eastnet-esp-null-alg
