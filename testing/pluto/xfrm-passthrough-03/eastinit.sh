/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east-passthrough-a
ipsec add west-east-passthrough-b
ipsec route west-east-passthrough-a
ipsec route west-east-passthrough-b
ipsec add west-east
../../guestbin/echo-server.sh -tcp -4 7 -daemon
echo "initdone"
