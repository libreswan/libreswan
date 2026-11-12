/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-compress
ipsec connectionstatus westnet-eastnet-compress
echo "initdone"
