: ==== start ====
TESTNAME=basic-pluto-07
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-twofish
/testing/pluto/basic-pluto-01/eroutewait.sh trap
