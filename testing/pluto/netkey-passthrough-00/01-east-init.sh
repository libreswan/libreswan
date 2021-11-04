/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east-passthrough
ipsec auto --route west-east-passthrough
ipsec auto --add west-east
../../guestbin/echod.sh
echo "initdone"
