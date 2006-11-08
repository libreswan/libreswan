: ==== start ====
TESTNAME=algo-pluto-02
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-ah-sha1
/testing/pluto/basic-pluto-01/eroutewait.sh trap
