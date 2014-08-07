/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east-passthrough
ipsec auto --route west-east-passthrough
ipsec auto --add west-east
echo "initdone"
