/testing/guestbin/swan-prep
ifconfig eth0 192.1.3.194 netmask 255.255.255.0
route add -net default gw 192.1.3.254
ipsec _stackmanager start 
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add modecfg-road-eastnet-psk
echo "initdone"
