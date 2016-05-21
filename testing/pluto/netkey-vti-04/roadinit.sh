/testing/guestbin/swan-prep
# replace IP to pseudo random (probably not really needed)
ifconfig eth0 192.1.3.194 netmask 255.255.255.0
route add -net default gw 192.1.3.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet
echo done
