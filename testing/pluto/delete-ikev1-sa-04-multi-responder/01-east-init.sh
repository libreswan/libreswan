/testing/guestbin/swan-prep --hostkeys
ipsec start
ipsec add west-east
../../guestbin/wait-until-pluto-started
echo "initdone"
