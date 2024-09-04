/testing/guestbin/swan-prep --46 --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add v6-tunnel-east-road
ipsec auto --status | grep v6-tunnel-east-road
echo "initdone"
