: ==== start ====
TESTNAME=netkey-psk-pluto-06
/testing/guestbin/swan-prep --testname $TESTNAME

ipsec setup stop
/usr/local/libexec/ipsec/_stackmanager stop
rm -fr /var/run/pluto/pluto.pid
/usr/local/libexec/ipsec/_stackmanager start
ipsec setup start:
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add road--eastnet-psk
ipsec auto --status
echo "initdone"
