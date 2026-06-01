/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-passthrough
ipsec route westnet-eastnet-passthrough
ipsec add westnet-eastnet
echo "initdone"
