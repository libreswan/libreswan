/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east-passthrough
ipsec route west-east-passthrough
ipsec add west-east
../../guestbin/echo-server.sh -tcp -4 7 -daemon
echo "initdone"
