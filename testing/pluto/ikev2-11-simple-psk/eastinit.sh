: ==== start ====
TESTNAME=ikev2-11-simple-psk
/testing/guestbin/swan-prep --testname $TESTNAME

ipsec setup stop
/usr/local/libexec/ipsec/_stackmanager stop
/usr/local/libexec/ipsec/_stackmanager start 
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add  westnet-eastnet-ipv4-psk-ikev2
ipsec whack --debug-control --debug-controlmore --debug-crypt
echo "initdone"
