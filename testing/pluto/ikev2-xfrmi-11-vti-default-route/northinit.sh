/testing/guestbin/swan-prep
ip link set vti0 down 2>/dev/null && ip link del vti0 2>/dev/null
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east
echo "initdone"
