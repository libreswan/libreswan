/testing/guestbin/swan-prep --nokeys --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec connectionstatus westnet-eastnet
echo "initdone"
