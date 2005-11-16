TESTNAME=basic-pluto-01
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet
ipsec whack --debug-control --debug-controlmore --debug-crypt
/testing/pluto/basic-pluto-01/eroutewait.sh trap
