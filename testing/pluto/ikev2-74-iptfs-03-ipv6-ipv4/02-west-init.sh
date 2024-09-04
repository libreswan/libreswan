/testing/guestbin/swan-prep --46 --nokey
ip addr show eth0 | grep global | sort
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east-tunnels
echo "initdone"
