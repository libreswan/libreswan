: ==== start ====
TESTNAME=algo-pluto-02
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-ah-sha1
/testing/pluto/basic-pluto-01/eroutewait.sh trap
