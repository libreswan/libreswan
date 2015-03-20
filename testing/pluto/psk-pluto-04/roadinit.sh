/testing/guestbin/swan-prep 
ifconfig eth0 inet 192.1.3.174
route add -net default gw 192.1.3.254
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east-psk
echo "initdone"
