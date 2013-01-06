: ==== start ====
TESTNAME=basic-pluto-11
/testing/guestbin/swanprep --testname $TESTNAME

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-ipv4
ipsec whack --debug-control --debug-controlmore --debug-crypt
echo "initdone"
