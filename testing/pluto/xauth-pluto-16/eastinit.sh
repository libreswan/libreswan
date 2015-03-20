/testing/guestbin/swan-prep --x509 
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add modecfg-east-21
ipsec auto --add modecfg-east-20
ipsec auto --add modecfg-road-east
echo initdone
