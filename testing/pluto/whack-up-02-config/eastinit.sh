/testing/guestbin/swan-prep --46 --nokey

../../guestbin/ifconfig.sh eth0 add 192.0.20.254/24
../../guestbin/ifconfig.sh eth0 add 2001:db8:0:20::254/64

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
echo "initdone"
