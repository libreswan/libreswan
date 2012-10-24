: ==== start ====
TESTNAME=interop-ikev2-strongswan-06-aes192
EAST_USERLAND="strongswan"
source /testing/pluto/bin/eastlocal.sh

/usr/local/strongswan/sbin/ipsec start
/testing/pluto/bin/wait-until-pluto-started
echo "initdone"
