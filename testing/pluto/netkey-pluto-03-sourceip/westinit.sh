: ==== start ====
TESTNAME=netkey-pluto-03-sourceip
source /testing/pluto/bin/westlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-east-sourceip
echo done

