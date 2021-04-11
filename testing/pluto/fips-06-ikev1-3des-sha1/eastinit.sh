/testing/guestbin/swan-prep
fipscheck
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
echo "initdone"
