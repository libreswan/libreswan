/testing/guestbin/swan-prep --nokeys
# confirm that the network is alive
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add eastnet-road
echo "initdone"
