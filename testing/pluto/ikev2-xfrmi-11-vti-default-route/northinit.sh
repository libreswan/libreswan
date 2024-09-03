/testing/guestbin/swan-prep --nokeys
../../guestbin/ip.sh link set vti0 down 2>/dev/null && ../../guestbin/ip.sh link del vti0 2>/dev/null
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east
echo "initdone"
