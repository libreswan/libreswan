/testing/guestbin/swan-prep 
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/_stackmanager stop
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road--eastnet-psk
ipsec auto --status
echo "initdone"
