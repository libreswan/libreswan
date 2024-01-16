/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east-ikev2
ipsec auto --status | grep west

../../guestbin/echo-server.sh -tcp -4 7 -daemon
sleep 1
echo 7 | ncat localhost 7

../../guestbin/echo-server.sh -tcp -4 333 -daemon
sleep 1
echo 333 | ncat localhost 333

echo "initdone"
