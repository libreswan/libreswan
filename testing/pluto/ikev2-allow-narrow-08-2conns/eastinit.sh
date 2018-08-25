/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east-ikev2
ipsec auto --status | grep west
echo "initdone"
