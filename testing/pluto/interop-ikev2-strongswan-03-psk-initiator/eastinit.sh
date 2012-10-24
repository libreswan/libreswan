: ==== start ====
TESTNAME=interop-ikev2-strongswan-03-psk-initiator
EAST_USERLAND="strongswan"
source /testing/pluto/bin/eastlocal.sh

/usr/local/strongswan/sbin/ipsec start
/testing/pluto/bin/wait-until-pluto-started
echo "initdone"
