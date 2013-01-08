: ==== start ====
TESTNAME=basic-pluto-01
/testing/guestbin/swanprep --testname $TESTNAME

ipsec setup stop
/usr/local/libexec/ipsec/_stackmanager stop
/usr/local/libexec/ipsec/_stackmanager start 
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 

/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet
ipsec whack --debug-control --debug-controlmore --debug-crypt
echo "initdone"
