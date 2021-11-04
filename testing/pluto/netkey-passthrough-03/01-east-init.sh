/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east-passthrough-a
ipsec auto --add west-east-passthrough-b
ipsec auto --route west-east-passthrough-a
ipsec auto --route west-east-passthrough-b
ipsec auto --add west-east
../../guestbin/echod.sh
echo "initdone"
