/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-northnet
ipsec auto --add eastnet-northnet
echo "initdone"
