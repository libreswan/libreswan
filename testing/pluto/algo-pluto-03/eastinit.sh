: ==== start ====
TESTNAME=algo-pluto-03
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/basic-pluto-01/eroutewait.sh trap

ipsec auto --add westnet-eastnet-ah-sha1-pfs
ipsec auto --add westnet-eastnet-ah-md5-pfs
