: ==== start ====
#TESTNAME=psk-pluto-01
#/testing/guestbin/swan-prep --testname $TESTNAME

/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add road--eastnet-psk
ipsec auto --status
echo "initdone"
