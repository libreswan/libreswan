TESTNAME=dh1-pluto-01
source /testing/pluto/bin/eastlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/basic-pluto-01/eroutewait.sh trap

ipsec auto --add westnet-eastnet-weak
