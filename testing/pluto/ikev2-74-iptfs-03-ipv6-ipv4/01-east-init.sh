/testing/guestbin/swan-prep --46 --nokey
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east-tunnels
echo "initdone"
