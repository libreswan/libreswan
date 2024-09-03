/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-to-east
echo "initdone"
