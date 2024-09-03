/testing/guestbin/swan-prep --nokeys
ifconfig eth0 192.1.3.194 netmask 255.255.255.0
route add -net default gw 192.1.3.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add modecfg-road-eastnet-psk
echo "initdone"
