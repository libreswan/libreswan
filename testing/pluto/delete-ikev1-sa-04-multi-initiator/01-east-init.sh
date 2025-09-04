/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east-c
ipsec add west-east-b
ipsec add west-east
echo "initdone"
