/testing/guestbin/swan-prep
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add modecfg-road--eastnet-psk
echo initdone
