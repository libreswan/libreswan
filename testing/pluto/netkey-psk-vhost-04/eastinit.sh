: ==== start ====
TESTNAME=netkey-psk-vhost-01
/testing/guestbin/swan-prep --testname $TESTNAME

ipsec setup stop
/usr/local/libexec/ipsec/_stackmanager stop
rm -fr /var/run/pluto/pluto.pid
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add road-east-psk
ipsec auto --status
echo "initdone"
