/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-subnets
ipsec status | grep westnet-eastnet
echo "initdone"
