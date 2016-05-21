: ==== start ====
TESTNAME=pluto-algo-01
source /testing/pluto/bin/westlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-cross
ipsec auto --up  westnet-eastnet-cross

echo done

