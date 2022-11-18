/testing/guestbin/swan-prep --46 --nokey

ip addr add 192.0.20.254/24 dev eth0
ip addr add 2001:db8:0:20::256/64 dev eth0
ip addr show eth0 | grep global | sort

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
echo "initdone"
