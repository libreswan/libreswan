/testing/guestbin/swan-prep
../../guestbin/ip.sh link set ipsec2 down 2>/dev/null && ../../guestbin/ip.sh link del ipsec2 2>/dev/null
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east
echo "initdone"
