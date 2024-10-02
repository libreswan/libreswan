ip addr add 192.1.4.45/24 dev eth0 2>/dev/null
ip addr add 192.1.4.23/24 dev eth0 2>/dev/null
/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add eastnet-northnet
echo "initdone"
