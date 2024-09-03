/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east
ipsec auto --add runner-east
echo "initdone"
