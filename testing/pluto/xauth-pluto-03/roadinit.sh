/testing/guestbin/swan-prep
ipsec _stackmanager start 
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add xauth-road--eastnet
ifconfig eth0 inet 192.1.3.194
route delete -net default 
route add -net default gw 192.1.3.254
route -n
echo done
