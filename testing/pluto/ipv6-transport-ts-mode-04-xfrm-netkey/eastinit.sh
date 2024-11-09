/testing/guestbin/swan-prep --46 --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add v6-transport
../../guestbin/echo-server.sh -tcp -6 1701 -daemon
echo "initdone"
