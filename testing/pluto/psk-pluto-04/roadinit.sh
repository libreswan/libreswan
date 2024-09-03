/testing/guestbin/swan-prep --nokeys
ifconfig eth0 inet 192.1.3.174
route add -net default gw 192.1.3.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east-psk
echo "initdone"
