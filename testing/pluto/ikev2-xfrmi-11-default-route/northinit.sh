/testing/guestbin/swan-prep
ip link set ipsec2 down 2>/dev/null && ip link del ipsec2 2>/dev/null
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east
echo "initdone"
