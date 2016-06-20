/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east-passthrough-a
ipsec auto --add west-east-passthrough-b
ipsec auto --route west-east-passthrough-a
ipsec auto --route west-east-passthrough-b
ipsec auto --add west-east
nc -4 -l 192.1.2.23 222 &
echo "initdone"
