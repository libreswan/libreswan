: ==== start ====
TESTNAME=algo-pluto-03
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-ah-sha1-pfs
ipsec auto --add westnet-eastnet-ah-md5-pfs
/testing/pluto/basic-pluto-01/eroutewait.sh trap
