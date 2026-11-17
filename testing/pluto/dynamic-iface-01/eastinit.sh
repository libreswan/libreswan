/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east
ipsec add float-east
ipsec add west-float
echo "initdone"
