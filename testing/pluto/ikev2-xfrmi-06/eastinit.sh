/testing/guestbin/swan-prep
# confirm that the network is alive
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add eastnet-road
echo "initdone"
