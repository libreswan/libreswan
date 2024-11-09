/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east-passthrough-a
ipsec auto --add west-east-passthrough-b
ipsec auto --route west-east-passthrough-a
ipsec auto --route west-east-passthrough-b
ipsec auto --add west-east
../../guestbin/echo-server.sh -tcp -4 7 -daemon
echo "initdone"
