/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east
ipsec add westnet-eastnet
echo "initdone"
