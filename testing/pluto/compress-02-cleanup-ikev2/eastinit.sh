/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ipcomp
echo "initdone"
