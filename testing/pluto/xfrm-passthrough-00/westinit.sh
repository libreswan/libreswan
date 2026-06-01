/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east
ipsec add west-east-passthrough
ipsec route west-east-passthrough
echo "initdone"
