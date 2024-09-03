/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --add pass-7
echo "initdone"
