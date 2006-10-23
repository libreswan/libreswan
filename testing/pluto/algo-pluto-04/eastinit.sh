: ==== start ====
TESTNAME=algo-pluto-04
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-esp-sha1-pfs
ipsec auto --add westnet-eastnet-esp-md5-pfs
/testing/pluto/basic-pluto-01/eroutewait.sh trap
