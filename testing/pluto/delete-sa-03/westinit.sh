/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --add west-east-b
ipsec auto --add west-east-c
ipsec auto --status | grep west-
echo "initdone"
