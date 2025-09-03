/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-east
ipsec add west-eastnet
ipsec add west-east
echo "initdone"
