: ==== start ====
TESTNAME=multinet-04
source /testing/pluto/bin/eastlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnets-eastnet

