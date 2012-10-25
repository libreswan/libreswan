: ==== start ====
TESTNAME=basic-pluto-04
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-aes128
/testing/pluto/basic-pluto-01/eroutewait.sh trap
echo "initdone"
